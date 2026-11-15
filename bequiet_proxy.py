#!/usr/bin/env python3
"""bequiet-proxy - HTTP + SOCKS5 proxy in front of https://bequiet.pages.dev/fonts/<url>

Single file, Python standard library only (no pip install required).

    python bequiet_proxy.py --http-port 9090 --socks-port 1080
    python bequiet_proxy.py --install-ca

The upstream service takes the target URL as a path suffix:

    https://duckduckgo.com   ->  https://bequiet.pages.dev/fonts/https://duckduckgo.com
    wss://echo.websocket.org  ->  wss://bequiet.pages.dev/fonts/wss://echo.websocket.org

A proxy cannot forward an already established TLS session that way, so this tool
terminates TLS locally (MITM) with a locally generated certificate authority and
re-issues every request through the service.
"""

import argparse
import base64
import hashlib
import http.client
import os
import re
import secrets
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

VERSION = "1.0.0"

HOP_BY_HOP = {
    "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
}

# ==========================================================================
# ASN.1 / DER 编码与解析 / ASN.1 DER encoding and parsing
# ==========================================================================


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def der_tlv(tag: int, content: bytes) -> bytes:
    if not isinstance(content, (bytes, bytearray)):
        raise TypeError("DER content must be bytes")
    return bytes([tag]) + _der_len(len(content)) + bytes(content)


def der_int(value) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value).lstrip(b"\x00") or b"\x00"
    else:
        value = int(value)
        raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big").lstrip(b"\x00") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return der_tlv(0x02, raw)


def der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        chunk = bytearray([value & 0x7F])
        value >>= 7
        while value:
            chunk.insert(0, (value & 0x7F) | 0x80)
            value >>= 7
        out += chunk
    return der_tlv(0x06, bytes(out))


def decode_oid(content: bytes) -> str:
    """解码 OBJECT IDENTIFIER 的内容字节。

    Decode the content octets of an OBJECT IDENTIFIER.
    """
    if not content:
        return ""
    values = [content[0] // 40, content[0] % 40]
    number = 0
    for byte in content[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(number)
            number = 0
    return ".".join(str(value) for value in values)


def der_seq(content: bytes) -> bytes:
    return der_tlv(0x30, content)


def der_set(content: bytes) -> bytes:
    return der_tlv(0x31, content)


def der_octet(content: bytes) -> bytes:
    return der_tlv(0x04, content)


def der_bitstring(content: bytes, unused: int = 0) -> bytes:
    return der_tlv(0x03, bytes([unused]) + content)


def der_bool(value: bool) -> bytes:
    return der_tlv(0x01, b"\xff" if value else b"\x00")


def der_utf8(text: str) -> bytes:
    return der_tlv(0x0C, text.encode("utf-8"))


def der_null() -> bytes:
    return der_tlv(0x05, b"")


def der_time(moment: datetime) -> bytes:
    if 1950 <= moment.year < 2050:
        text = "%02d%02d%02d%02d%02d%02dZ" % (
            moment.year % 100, moment.month, moment.day,
            moment.hour, moment.minute, moment.second)
        return der_tlv(0x17, text.encode("ascii"))
    text = "%04d%02d%02d%02d%02d%02dZ" % (
        moment.year, moment.month, moment.day,
        moment.hour, moment.minute, moment.second)
    return der_tlv(0x18, text.encode("ascii"))


def der_name(entries) -> bytes:
    """构造 Name 结构：entries 为 (oid, value) 序列。

    Build a Name (RDNSequence); entries is an iterable of (oid, value) pairs.
    """
    parts = []
    for oid, value in entries:
        parts.append(der_set(der_seq(der_oid(oid) + der_utf8(value))))
    return der_seq(b"".join(parts))


def der_ext(oid: str, critical: bool, value: bytes) -> bytes:
    body = der_oid(oid)
    if critical:
        body += der_bool(True)
    body += der_octet(value)
    return der_seq(body)


def ext_basic_constraints(is_ca: bool, path_len=None) -> bytes:
    body = der_bool(True) if is_ca else b""
    if path_len is not None:
        body += der_int(path_len)
    return der_seq(body)


def ext_key_usage(bits: int, unused: int) -> bytes:
    return der_bitstring(bytes([bits]), unused)


def ext_eku(oids) -> bytes:
    return der_seq(b"".join(der_oid(o) for o in oids))


def ext_san_dns(names) -> bytes:
    return der_seq(b"".join(der_tlv(0x82, n.encode("ascii")) for n in names))


def ext_san_ip(address: str) -> bytes:
    if ":" in address:
        raw = bytes.fromhex(address.replace(":", ""))
    else:
        raw = bytes(int(part) for part in address.split("."))
    return der_tlv(0x87, raw)


def ext_ski(key_id: bytes) -> bytes:
    return der_octet(key_id)


def ext_aki(key_id: bytes) -> bytes:
    return der_seq(der_tlv(0x80, key_id))


def ext_crl_dp(url: str) -> bytes:
    """CRL 分发点扩展，指向一个 HTTP URL。

    CRL Distribution Points pointing at a single HTTP URL.
    """
    general_name = der_tlv(0x86, url.encode("ascii"))
    full_name = der_tlv(0xA0, general_name)          # fullName [0] GeneralNames
    distribution_point = der_seq(der_tlv(0xA0, full_name))
    return der_seq(distribution_point)


# --- minimal DER reader ---------------------------------------------------


def der_read(buf: bytes, offset: int) -> dict:
    header = offset
    tag = buf[offset]
    offset += 1
    length = buf[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        length = 0
        for _ in range(count):
            length = (length << 8) | buf[offset]
            offset += 1
    return {"tag": tag, "start": offset, "end": offset + length,
            "len": length, "header": header}


def der_children(buf: bytes, node: dict) -> list:
    out = []
    offset = node["start"]
    while offset < node["end"]:
        child = der_read(buf, offset)
        out.append(child)
        offset = child["end"]
    return out


def der_raw(buf: bytes, node: dict) -> bytes:
    return buf[node["header"]:node["end"]]


def der_content(buf: bytes, node: dict) -> bytes:
    return buf[node["start"]:node["end"]]


def pem_encode(der: bytes, label: str) -> str:
    text = base64.b64encode(der).decode("ascii")
    lines = [text[i:i + 64] for i in range(0, len(text), 64)]
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, "\n".join(lines), label)


def pem_decode(pem: str) -> bytes:
    body = re.sub(r"-----(BEGIN|END)[^-]*-----", "", pem)
    return base64.b64decode(re.sub(r"\s+", "", body))


# ==========================================================================
# ECDSA over NIST P-256（纯 Python 实现）/ ECDSA over NIST P-256 (pure python)
# ==========================================================================

_EC_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_EC_A = _EC_P - 3
_EC_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_EC_G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
         0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _ec_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _EC_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0] + _EC_A) * pow(2 * p[1], -1, _EC_P) % _EC_P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _EC_P) % _EC_P
    x = (lam * lam - p[0] - q[0]) % _EC_P
    y = (lam * (p[0] - x) - p[1]) % _EC_P
    return (x, y)


def _ec_mul(k: int, point):
    result = None
    while k:
        if k & 1:
            result = _ec_add(result, point)
        point = _ec_add(point, point)
        k >>= 1
    return result


def ec_generate_key() -> dict:
    d = secrets.randbelow(_EC_N - 1) + 1
    return {"d": d, "public": _ec_mul(d, _EC_G)}


def ec_sign(d: int, message: bytes) -> bytes:
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    while True:
        k = secrets.randbelow(_EC_N - 1) + 1
        point = _ec_mul(k, _EC_G)
        r = point[0] % _EC_N
        if r == 0:
            continue
        s = pow(k, -1, _EC_N) * (z + r * d) % _EC_N
        if s == 0:
            continue
        return der_seq(der_int(r) + der_int(s))


def ec_spki(public_point) -> bytes:
    algorithm = der_seq(der_oid("1.2.840.10045.2.1") + der_oid("1.2.840.10045.3.1.7"))
    raw = b"\x04" + public_point[0].to_bytes(32, "big") + public_point[1].to_bytes(32, "big")
    return der_seq(algorithm + der_bitstring(raw, 0))


def ec_private_pem(key: dict) -> str:
    raw = b"\x04" + key["public"][0].to_bytes(32, "big") + key["public"][1].to_bytes(32, "big")
    body = der_seq(
        der_int(1)
        + der_octet(key["d"].to_bytes(32, "big"))
        + der_tlv(0xA0, der_oid("1.2.840.10045.3.1.7"))
        + der_tlv(0xA1, der_bitstring(raw, 0))
    )
    return pem_encode(body, "EC PRIVATE KEY")


# ==========================================================================
# RSA（PKCS#1 v1.5 签名，用于复用已有的 RSA CA）/ RSA PKCS#1 v1.5 signing
# ==========================================================================

_OID_RSA = "1.2.840.113549.1.1.1"
_OID_EC = "1.2.840.10045.2.1"
_OID_SHA256_RSA = "1.2.840.113549.1.1.11"
_OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"


def rsa_sign(n: int, d: int, message: bytes) -> bytes:
    digest = hashlib.sha256(message).digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    size = (n.bit_length() + 7) // 8
    padding = b"\xff" * (size - 3 - len(digest_info))
    block = b"\x00\x01" + padding + b"\x00" + digest_info
    signature = pow(int.from_bytes(block, "big"), d, n)
    return signature.to_bytes(size, "big")


def _load_sec1_ec(der: bytes) -> dict:
    """解析 SEC1 格式的 EC 私钥。

    SEC1 ECPrivateKey ::= SEQUENCE { version, privateKey OCTET STRING, ... }
    """
    node = der_read(der, 0)
    fields = der_children(der, node)
    d = int.from_bytes(der_content(der, fields[1]), "big")
    return {"type": "ec", "d": d, "public": _ec_mul(d, _EC_G)}


def _load_pkcs1_rsa(der: bytes) -> dict:
    """解析 PKCS#1 格式的 RSA 私钥。

    RSAPrivateKey ::= SEQUENCE { version, n, e, d, ... }
    """
    node = der_read(der, 0)
    fields = der_children(der, node)
    n = int.from_bytes(der_content(der, fields[1]), "big")
    d = int.from_bytes(der_content(der, fields[3]), "big")
    return {"type": "rsa", "n": n, "d": d}


def load_private_key(pem: str) -> dict:
    """从 PEM 载入私钥，支持 PKCS#8 / SEC1 EC / PKCS#1 RSA。

    Load a private key from PEM: PKCS#8, SEC1 EC or PKCS#1 RSA.
    """
    der = pem_decode(pem)
    label = ""
    match = re.search(r"-----BEGIN ([A-Z0-9 ]+)-----", pem)
    if match:
        label = match.group(1)
    if label == "EC PRIVATE KEY":
        return _load_sec1_ec(der)
    if label == "RSA PRIVATE KEY":
        return _load_pkcs1_rsa(der)
    info = der_read(der, 0)
    parts = der_children(der, info)
    if len(parts) < 3:
        raise ValueError("unsupported private key format")
    algorithm = der_children(der, parts[1])
    key_oid = decode_oid(der_content(der, algorithm[0]))
    inner = der_content(der, parts[2])
    if key_oid == _OID_RSA:
        return _load_pkcs1_rsa(inner)
    if key_oid == _OID_EC:
        return _load_sec1_ec(inner)
    raise ValueError("unsupported private key algorithm " + key_oid)


# ==========================================================================
# 本地证书颁发机构 / Local certificate authority
# ==========================================================================


class CertificateAuthority:
    """本地根证书颁发机构：为被拦截的域名现场签发叶子证书。

    Local root CA. Mints leaf certificates for intercepted hosts.
    """

    def __init__(self, directory, crl_url=None, cert_path=None, key_path=None,
                 cn="bequiet MITM CA", org="bequiet-proxy"):
        self.dir = os.path.abspath(directory)
        self.leaf_dir = os.path.join(self.dir, "leaves")
        os.makedirs(self.leaf_dir, exist_ok=True)
        self.cert_path = os.path.join(self.dir, "ca.crt")
        self.key_path = os.path.join(self.dir, "ca.key")
        self.der_path = os.path.join(self.dir, "ca.cer")
        self.crl_url = crl_url
        self._leaves = {}
        self._lock = threading.Lock()

        if cert_path and key_path:
            self._load(cert_path, key_path)
        elif os.path.exists(self.cert_path) and os.path.exists(self.key_path):
            self._load(self.cert_path, self.key_path)
        else:
            self._create(cn, org)

    # -- creation ---------------------------------------------------------

    def _create(self, cn, org):
        key = ec_generate_key()
        spki = ec_spki(key["public"])
        key_id = hashlib.sha1(spki).digest()
        subject = der_name([("2.5.4.10", org), ("2.5.4.3", cn)])
        extensions = der_seq(
            der_ext("2.5.29.19", True, ext_basic_constraints(True, 0))
            + der_ext("2.5.29.15", True, ext_key_usage(0x06, 1))
            + der_ext("2.5.29.14", False, ext_ski(key_id))
            + der_ext("2.5.29.35", False, ext_aki(key_id))
        )
        self.key = {"type": "ec", "d": key["d"], "public": key["public"]}
        self.subject_der = subject
        self.spki_der = spki
        self.key_id = key_id
        now = datetime.now(timezone.utc)
        self.der = self._build_cert(subject, spki, extensions,
                                    now - timedelta(days=1), now + timedelta(days=3650))
        self.pem = pem_encode(self.der, "CERTIFICATE")
        self.key_pem = ec_private_pem(key)
        self._save()

    def _load(self, cert_path, key_path):
        with open(cert_path, "r", encoding="ascii") as handle:
            self.pem = handle.read()
        with open(key_path, "r", encoding="ascii") as handle:
            self.key_pem = handle.read()
        self.der = pem_decode(self.pem)
        cert = der_read(self.der, 0)
        fields = der_children(self.der, der_children(self.der, cert)[0])
        self.subject_der = der_raw(self.der, fields[5])
        self.spki_der = der_raw(self.der, fields[6])
        self.key_id = hashlib.sha1(self.spki_der).digest()
        self.key = load_private_key(self.key_pem)
        self._save()

    def _save(self):
        with open(self.cert_path, "w", encoding="ascii") as handle:
            handle.write(self.pem)
        with open(self.key_path, "w", encoding="ascii") as handle:
            handle.write(self.key_pem)
        with open(self.der_path, "wb") as handle:
            handle.write(self.der)

    # -- signing ----------------------------------------------------------

    def _algorithm(self) -> bytes:
        if self.key["type"] == "rsa":
            return der_seq(der_oid(_OID_SHA256_RSA) + der_null())
        return der_seq(der_oid(_OID_ECDSA_SHA256))

    def _sign(self, data: bytes) -> bytes:
        if self.key["type"] == "rsa":
            return rsa_sign(self.key["n"], self.key["d"], data)
        return ec_sign(self.key["d"], data)

    def _build_cert(self, subject_der, spki_der, extensions, not_before, not_after) -> bytes:
        algorithm = self._algorithm()
        serial = der_int(secrets.token_bytes(16))
        tbs = der_seq(
            der_tlv(0xA0, der_int(2))
            + serial
            + algorithm
            + self.subject_der
            + der_seq(der_time(not_before) + der_time(not_after))
            + subject_der
            + spki_der
            + der_tlv(0xA3, extensions)
        )
        return der_seq(tbs + algorithm + der_bitstring(self._sign(tbs), 0))

    # -- public API -------------------------------------------------------

    def thumbprint(self) -> str:
        return hashlib.sha1(self.der).hexdigest().upper()

    def leaf(self, host: str) -> dict:
        """为指定域名或 IP 签发（并缓存）叶子证书。

    Mint (and cache) a leaf certificate for the given host name or IP.
    """
        key = host.lower()
        with self._lock:
            cached = self._leaves.get(key)
        if cached:
            return cached
        pair = ec_generate_key()
        spki = ec_spki(pair["public"])
        key_id = hashlib.sha1(spki).digest()
        subject = der_name([("2.5.4.3", host)])
        try:
            socket.inet_pton(socket.AF_INET, host)
            is_ip = True
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, host)
                is_ip = True
            except OSError:
                is_ip = False
        san = der_seq(ext_san_ip(host)) if is_ip else ext_san_dns([host])
        extensions = der_seq(
            der_ext("2.5.29.19", True, ext_basic_constraints(False))
            + der_ext("2.5.29.15", True, ext_key_usage(0xA0, 5))
            + der_ext("2.5.29.37", False, ext_eku(["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]))
            + der_ext("2.5.29.17", False, san)
            + (der_ext("2.5.29.31", False, ext_crl_dp(self.crl_url)) if self.crl_url else b"")
            + der_ext("2.5.29.14", False, ext_ski(key_id))
            + der_ext("2.5.29.35", False, ext_aki(self.key_id))
        )
        now = datetime.now(timezone.utc)
        der = self._build_cert(subject, spki, extensions,
                                now - timedelta(hours=1), now + timedelta(days=397))
        cert_pem = pem_encode(der, "CERTIFICATE")
        key_pem = ec_private_pem(pair)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)
        cert_file = os.path.join(self.leaf_dir, safe + ".crt")
        key_file = os.path.join(self.leaf_dir, safe + ".key")
        with open(cert_file, "w", encoding="ascii") as handle:
            handle.write(cert_pem)
        with open(key_file, "w", encoding="ascii") as handle:
            handle.write(key_pem)
        leaf = {"host": host, "der": der, "cert": cert_pem, "key": key_pem,
                "cert_file": cert_file, "key_file": key_file}
        with self._lock:
            self._leaves[key] = leaf
        return leaf

    def crl(self) -> bytes:
        """生成空的证书吊销列表（当前未吊销任何证书）。

    Empty (nothing revoked) CRL signed by this CA.
    """
        algorithm = self._algorithm()
        now = datetime.now(timezone.utc)
        extensions = der_seq(der_ext("2.5.29.35", False, ext_aki(self.key_id)))
        tbs = der_seq(
            der_int(1)
            + algorithm
            + self.subject_der
            + der_time(now)
            + der_time(now + timedelta(days=7))
            + der_tlv(0xA0, extensions)
        )
        return der_seq(tbs + algorithm + der_bitstring(self._sign(tbs), 0))


# ==========================================================================
# HTTP 请求解析 / HTTP request parsing
# ==========================================================================


class RequestReader:
    """增量式 HTTP/1.1 请求读取器。

    Incremental HTTP/1.1 request reader.
    """

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _recv(self):
        data = self.sock.recv(65536)
        if not data:
            raise ConnectionError("peer closed the connection")
        self.buf += data

    def next_request(self):
        while b"\r\n\r\n" not in self.buf:
            self._recv()
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        method, target, version = lines[0].decode("latin1").split(" ", 2)
        headers = {}
        for raw in lines[1:]:
            if not raw:
                continue
            name, _, value = raw.decode("latin1").partition(":")
            headers[name.strip().lower()] = value.strip()
        return method, target, version, headers

    def read_exact(self, count):
        while len(self.buf) < count:
            self._recv()
        data, self.buf = self.buf[:count], self.buf[count:]
        return data

    def read_line(self):
        while b"\r\n" not in self.buf:
            self._recv()
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def body(self, headers):
        encoding = headers.get("transfer-encoding", "").lower()
        if "chunked" in encoding:
            return self._read_chunked()
        length = headers.get("content-length")
        if length:
            try:
                return self._read_fixed(int(length))
            except ValueError:
                return iter(())
        return iter(())

    def _read_fixed(self, count):
        remaining = count
        while remaining > 0:
            if not self.buf:
                self._recv()
            take = min(remaining, len(self.buf))
            chunk, self.buf = self.buf[:take], self.buf[take:]
            remaining -= take
            yield chunk

    def _read_chunked(self):
        while True:
            line = self.read_line()
            try:
                size = int(line.split(b";")[0].strip(), 16)
            except ValueError:
                return
            if size == 0:
                while True:
                    trailer = self.read_line()
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                return
            yield self.read_exact(size)
            self.read_exact(2)


def peek_until(sock, marker: bytes) -> int:
    """探测需要读取多少字节才能遇到标记，期间不消费任何数据。

    Return how many bytes are needed to reach marker, without consuming them.
    """
    buf = b""
    while True:
        chunk = sock.recv(4096, socket.MSG_PEEK)
        if not chunk:
            raise ConnectionError("peer closed the connection")
        buf += chunk
        index = buf.find(marker)
        if index >= 0:
            return index + len(marker)


# ==========================================================================
# WebSocket 帧编解码（RFC 6455，不支持扩展）/ WebSocket frames (RFC 6455)
# ==========================================================================

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_accept(key: str) -> str:
    digest = hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def ws_encode(opcode: int, payload: bytes, mask: bool = False) -> bytes:
    header = bytearray([0x80 | opcode])
    length = len(payload)
    flag = 0x80 if mask else 0x00
    if length < 126:
        header.append(flag | length)
    elif length < 65536:
        header.append(flag | 126)
        header += struct.pack(">H", length)
    else:
        header.append(flag | 127)
        header += struct.pack(">Q", length)
    if mask:
        key = secrets.token_bytes(4)
        masked = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
        return bytes(header) + key + masked
    return bytes(header) + bytes(payload)


class WebSocketReader:
    """从字节流中解析 WebSocket 帧。

    Parses WebSocket frames out of a byte stream.
    """

    def __init__(self, on_message=None, on_ping=None, on_close=None):
        self.on_message = on_message
        self.on_ping = on_ping
        self.on_close = on_close
        self.buf = b""
        self.fragments = []
        self.fragment_opcode = 0

    def feed(self, data: bytes):
        if not data:
            return
        self.buf += data
        while True:
            if len(self.buf) < 2:
                return
            first, second = self.buf[0], self.buf[1]
            fin = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            offset = 2
            if length == 126:
                if len(self.buf) < 4:
                    return
                length = struct.unpack(">H", self.buf[2:4])[0]
                offset = 4
            elif length == 127:
                if len(self.buf) < 10:
                    return
                length = struct.unpack(">Q", self.buf[2:10])[0]
                offset = 10
            mask_key = None
            if masked:
                if len(self.buf) < offset + 4:
                    return
                mask_key = self.buf[offset:offset + 4]
                offset += 4
            if len(self.buf) < offset + length:
                return
            payload = bytearray(self.buf[offset:offset + length])
            if mask_key:
                for index in range(len(payload)):
                    payload[index] ^= mask_key[index % 4]
            self.buf = self.buf[offset + length:]
            self._handle(fin, opcode, bytes(payload))

    def _handle(self, fin, opcode, payload):
        if opcode == 0x8:
            if self.on_close:
                self.on_close(payload)
        elif opcode == 0x9:
            if self.on_ping:
                self.on_ping(payload)
        elif opcode == 0xA:
            pass
        elif opcode == 0x0:
            self.fragments.append(payload)
            if fin:
                data = b"".join(self.fragments)
                opcode = self.fragment_opcode
                self.fragments = []
                self.fragment_opcode = 0
                if self.on_message:
                    self.on_message(opcode, data)
        elif not fin:
            self.fragment_opcode = opcode
            self.fragments = [payload]
        elif self.on_message:
            self.on_message(opcode, payload)


# ==========================================================================
# 上游服务（bequiet）/ Upstream (the bequiet service)
# ==========================================================================

_UNSAFE_PATH_CHARS = frozenset('"<>^' + chr(96) + '{}|' + chr(92))


class Upstream:
    """到 bequiet 服务的 HTTPS 连接池。

    Pooled HTTPS connections to the bequiet service.
    """

    def __init__(self, base_url: str, timeout: float = 90):
        parsed = urlsplit(base_url)
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.host_header = self.host if self.port == 443 else "%s:%d" % (self.host, self.port)
        self.timeout = timeout
        self.context = ssl.create_default_context()
        self._idle = []
        self._lock = threading.Lock()

    def acquire(self):
        with self._lock:
            while self._idle:
                conn = self._idle.pop()
                if conn.sock is None:
                    continue
                try:
                    readable = select.select([conn.sock], [], [], 0)[0]
                except Exception:
                    readable = [conn.sock]
                if readable:
                    # the peer closed the idle connection: do not reuse it
                    self.discard(conn)
                    continue
                return conn
        return http.client.HTTPSConnection(self.host, self.port,
                                          context=self.context, timeout=self.timeout)

    def discard(self, conn):
        """丢弃连接，不放回连接池。

    Throw a connection away instead of returning it to the pool.
    """
        try:
            conn.close()
        except Exception:
            pass

    def release(self, conn):
        if conn.sock is not None:
            with self._lock:
                self._idle.append(conn)
        else:
            try:
                conn.close()
            except Exception:
                pass


def encode_target_path(text: str) -> str:
    out = []
    for char in text:
        code = ord(char)
        if code <= 0x20 or code >= 0x7F or char in _UNSAFE_PATH_CHARS:
            out.append("".join("%%%02X" % byte for byte in char.encode("utf-8")))
        else:
            out.append(char)
    return "".join(out)


def filter_request_headers(headers: dict) -> dict:
    drop = set(HOP_BY_HOP)
    for value in headers.get("connection", "").split(","):
        name = value.strip().lower()
        if name:
            drop.add(name)
    out = {}
    for name, value in headers.items():
        low = name.lower()
        if low in drop or low in ("host", "expect", "accept-encoding"):
            continue
        out[name] = value
    return out


# ==========================================================================
# 代理核心 / Proxy core
# ==========================================================================


class Proxy:
    def __init__(self, upstream_url, ca, verbose=False, socks_auth=None,
                 socks_tls="auto", crl_path=None):
        self.upstream = Upstream(upstream_url)
        self.ca = ca
        self.verbose = verbose
        self.socks_auth = socks_auth
        self.socks_tls = socks_tls
        self.crl_path = crl_path
        self.http_server = None
        self.socks_server = None

    def log(self, *args):
        if self.verbose:
            print("[%s]" % datetime.now(timezone.utc).isoformat(), *args, flush=True)

    # -- URL mapping ------------------------------------------------------

    def upstream_path(self, url: str, websocket: bool = False) -> str:
        parts = urlsplit(url)
        rest = parts.path or "/"
        if parts.query:
            rest += "?" + parts.query
        host = parts.netloc
        if websocket:
            return "/fonts/wss://" + encode_target_path(host + rest)
        scheme = parts.scheme or "https"
        return "/fonts/" + scheme + "://" + encode_target_path(host + rest)

    def wants_tls(self, port: int) -> bool:
        if self.socks_tls == "always":
            return True
        if self.socks_tls == "never":
            return False
        return port in (443, 8443, 9443, 465)

    # -- listeners --------------------------------------------------------

    def listen(self, http_port, socks_port, host):
        self.http_server = self._listener(http_port, host, self.handle_http_client)
        self.socks_server = self._listener(socks_port, host, self.handle_socks_client)

    def _listener(self, port, host, handler):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Windows 上 SO_REUSEADDR 允许别的进程抢占同一端口（Unix 上不会），
        # 这里改用 SO_EXCLUSIVEADDRUSE：既防止被抢，也能忽略 TIME_WAIT 残留。
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(128)

        def loop():
            while True:
                try:
                    client, _peer = listener.accept()
                except OSError:
                    return
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                thread = threading.Thread(target=self._guard, args=(handler, client), daemon=True)
                thread.start()

        threading.Thread(target=loop, daemon=True).start()
        return listener

    @staticmethod
    def _guard(handler, client):
        try:
            handler(client)
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        except Exception:
            traceback.print_exc()
        finally:
            try:
                client.close()
            except Exception:
                pass

    @staticmethod
    def absolute_url(target, host, port, secure):
        if target.startswith("http://") or target.startswith("https://"):
            return target
        if not host:
            return target
        scheme = "https" if secure else "http"
        suffix = "" if port in (80, 443) else ":%d" % port
        path = target if target.startswith("/") else "/" + target
        return scheme + "://" + host + suffix + path

    # -- HTTP proxy -------------------------------------------------------

    def handle_http_client(self, sock, default_host=None, default_port=None, secure=False):
        # Peek at the request head so that a CONNECT request is consumed
        # byte-exactly: the TLS layer below has to read the ClientHello itself.
        needed = peek_until(sock, b"\r\n\r\n")
        head = b""
        while len(head) < needed:
            chunk = sock.recv(needed - len(head))
            if not chunk:
                return
            head += chunk
        reader = RequestReader(sock)
        reader.buf = head
        method, target, _version, headers = reader.next_request()
        if method.upper() == "CONNECT":
            self.handle_connect(sock, target)
            return
        while True:
            url = self.absolute_url(target, default_host, default_port, secure)
            if not self.handle_request(sock, reader, method, url, headers):
                return
            try:
                method, target, _version, headers = reader.next_request()
            except (ConnectionError, OSError):
                return

    def handle_connect(self, sock, target):
        host, _, port_text = target.rpartition(":")
        if not host:
            host, port_text = target, "443"
        try:
            port = int(port_text)
        except ValueError:
            port = 443
        host = host.strip("[]")
        self.log("CONNECT", "%s:%d" % (host, port))
        sock.sendall(b"HTTP/1.1 200 Connection Established\r\n"
                     b"Proxy-Agent: bequiet-proxy\r\nContent-Length: 0\r\n\r\n")
        secure_sock = self.tls_wrap(sock, host)
        self.serve_origin(secure_sock, host, port)

    def serve_origin(self, sock, host, port):
        """处理已建立的（被 MITM 解密的）TLS 会话内到达的请求。

    Serve requests that arrive inside an established (MITM) TLS session.
    """
        reader = RequestReader(sock)
        while True:
            try:
                method, target, _version, headers = reader.next_request()
            except (ConnectionError, OSError):
                return
            url = self.absolute_url(target, host, port, True)
            if headers.get("upgrade", "").lower() == "websocket":
                self.handle_websocket(sock, reader, headers, url)
                return
            if not self.handle_request(sock, reader, method, url, headers):
                return

    def handle_request(self, sock, reader, method, url, headers):
        parsed = urlsplit(url)
        if self.crl_path and parsed.path == self.crl_path:
            crl = self.ca.crl()
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/pkix-crl\r\n"
                         b"Content-Length: %d\r\nCache-Control: public, max-age=3600\r\n\r\n"
                         % len(crl) + crl)
            return
        upstream_headers = filter_request_headers(headers)
        upstream_headers["Host"] = self.upstream.host_header
        path = self.upstream_path(url)
        is_head = method.upper() == "HEAD"
        # the upstream service has no HEAD handler: ask for GET and drop the body
        upstream_method = "GET" if is_head else method
        length = headers.get("content-length")
        chunked = "chunked" in headers.get("transfer-encoding", "").lower()
        try:
            has_body = chunked or (length is not None and int(length) > 0)
        except ValueError:
            has_body = False
        body = reader.body(headers) if has_body else None
        self.log("HTTP", method, url, "->", path)
        close_connection = headers.get("connection", "").lower() == "close"
        # a request without a body can safely be retried on a fresh connection
        attempts = 2 if not has_body else 1
        response = None
        failure = None
        for attempt in range(attempts):
            conn = self.upstream.acquire()
            try:
                conn.request(upstream_method, path, body=body, headers=upstream_headers)
                response = conn.getresponse()
                break
            except TimeoutError:
                self.upstream.discard(conn)
                failure = (504, "Gateway Timeout",
                           "upstream timeout after %d seconds" % int(self.upstream.timeout))
                break
            except Exception as exc:
                self.upstream.discard(conn)
                if attempt + 1 < attempts:
                    self.log("upstream connection failed, retrying:", exc)
                    continue
                failure = (502, "Bad Gateway", "proxy upstream error: %s" % exc)
                break
        if response is None:
            status, reason, message = failure
            self.log("upstream error:", message)
            try:
                sock.sendall(("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\n\r\n%s\n"
                              % (status, reason, message)).encode("utf-8", "replace"))
            except Exception:
                pass
            return False
        try:
            self.send_response(sock, response, is_head, close_connection)
        finally:
            self.upstream.release(conn)
        return not close_connection

    @staticmethod
    def send_response(sock, response, is_head, close_connection=False):
        lines = ["HTTP/1.1 %d %s" % (response.status, response.reason or "")]
        for name, value in response.getheaders():
            low = name.lower()
            if low in HOP_BY_HOP:
                continue
            if low == "content-length" and not is_head:
                continue
            lines.append("%s: %s" % (name, value))
        if not is_head:
            lines.append("Transfer-Encoding: chunked")
        lines.append("Connection: close" if close_connection else "Connection: keep-alive")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace"))
        if is_head:
            response.read()
            return
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            sock.sendall(b"%X\r\n" % len(chunk) + chunk + b"\r\n")
        sock.sendall(b"0\r\n\r\n")

    # -- TLS ---------------------------------------------------------------

    def tls_wrap(self, sock, host):
        leaf = self.ca.leaf(host)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(leaf["cert_file"], leaf["key_file"])
        context.set_alpn_protocols(["http/1.1"])
        return context.wrap_socket(sock, server_side=True)

    # -- WebSocket ---------------------------------------------------------

    def handle_websocket(self, sock, reader, headers, url):
        client_key = headers.get("sec-websocket-key", "")
        client_protocols = headers.get("sec-websocket-protocol")
        path = self.upstream_path(url, websocket=True)
        self.log("WS", url, "->", path)
        try:
            raw = socket.create_connection((self.upstream.host, self.upstream.port), timeout=60)
            upstream_sock = self.upstream.context.wrap_socket(raw, server_hostname=self.upstream.host)
        except Exception as exc:
            try:
                sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\n"
                             + ("websocket upstream error: %s\n" % exc).encode("utf-8", "replace"))
            except Exception:
                pass
            return
        request = [
            "GET %s HTTP/1.1" % path,
            "Host: %s" % self.upstream.host_header,
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: %s" % base64.b64encode(secrets.token_bytes(16)).decode(),
            "Sec-WebSocket-Version: 13",
        ]
        if client_protocols:
            request.append("Sec-WebSocket-Protocol: %s" % client_protocols)
        upstream_sock.sendall(("\r\n".join(request) + "\r\n\r\n").encode("latin-1"))

        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = upstream_sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode("latin-1", "replace") if head else ""
        if " 101 " not in status:
            self.log("ws upstream refused:", status)
            try:
                sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\n"
                             + ("upstream websocket handshake failed: %s\n" % status).encode("utf-8", "replace"))
            except Exception:
                pass
            upstream_sock.close()
            return
        reply = [
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Accept: %s" % ws_accept(client_key),
        ]
        match = re.search(r"sec-websocket-protocol:\s*([^\r\n]+)", head.decode("latin-1", "replace"), re.I)
        if match:
            reply.append("Sec-WebSocket-Protocol: %s" % match.group(1).strip())
        sock.sendall(("\r\n".join(reply) + "\r\n\r\n").encode("latin-1"))

        def to_upstream(opcode, payload):
            try:
                upstream_sock.sendall(ws_encode(opcode, payload, mask=True))
            except Exception:
                pass

        def to_client(opcode, payload):
            try:
                sock.sendall(ws_encode(opcode, payload, mask=False))
            except Exception:
                pass

        def client_closed(payload):
            to_upstream(0x8, payload)
            try:
                upstream_sock.close()
            except Exception:
                pass

        def upstream_closed(payload):
            to_client(0x8, payload)
            try:
                sock.close()
            except Exception:
                pass

        client_reader = WebSocketReader(
            on_message=to_upstream,
            on_ping=lambda payload: to_client(0xA, payload),
            on_close=client_closed)
        upstream_reader = WebSocketReader(
            on_message=to_client,
            on_ping=lambda payload: to_upstream(0xA, payload),
            on_close=upstream_closed)

        def pump():
            try:
                while True:
                    data = upstream_sock.recv(65536)
                    if not data:
                        break
                    upstream_reader.feed(data)
            except Exception:
                pass

        thread = threading.Thread(target=pump, daemon=True)
        thread.start()
        if reader.buf:
            client_reader.feed(reader.buf)
        if rest:
            upstream_reader.feed(rest)
        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                client_reader.feed(data)
        except Exception:
            pass
        try:
            upstream_sock.close()
        except Exception:
            pass

    # -- SOCKS5 ------------------------------------------------------------

    @staticmethod
    def read_exact(sock, count):
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            if not chunk:
                raise ConnectionError("peer closed the connection")
            data += chunk
        return data

    def handle_socks_client(self, sock):
        version, count = self.read_exact(sock, 2)
        if version != 5:
            return
        methods = self.read_exact(sock, count)
        if self.socks_auth:
            if 2 not in methods:
                sock.sendall(b"\x05\xff")
                return
            sock.sendall(b"\x05\x02")
            self.read_exact(sock, 1)
            user_len = self.read_exact(sock, 1)[0]
            user = self.read_exact(sock, user_len).decode("utf-8", "replace")
            pass_len = self.read_exact(sock, 1)[0]
            password = self.read_exact(sock, pass_len).decode("utf-8", "replace")
            if user != self.socks_auth[0] or password != self.socks_auth[1]:
                sock.sendall(b"\x01\x01")
                return
            sock.sendall(b"\x01\x00")
        else:
            if 0 not in methods:
                sock.sendall(b"\x05\xff")
                return
            sock.sendall(b"\x05\x00")
        head = self.read_exact(sock, 4)
        command, address_type = head[1], head[3]
        if address_type == 1:
            host = ".".join(str(byte) for byte in self.read_exact(sock, 4))
        elif address_type == 3:
            length = self.read_exact(sock, 1)[0]
            host = self.read_exact(sock, length).decode("utf-8", "replace")
        elif address_type == 4:
            raw = self.read_exact(sock, 16)
            host = ":".join("%x" % struct.unpack(">H", raw[i:i + 2])[0] for i in range(0, 16, 2))
        else:
            return
        port = struct.unpack(">H", self.read_exact(sock, 2))[0]
        if command != 1:
            sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        self.log("SOCKS", "%s:%d" % (host, port))
        if self.wants_tls(port):
            secure_sock = self.tls_wrap(sock, host)
            self.serve_origin(secure_sock, host, port)
        else:
            self.handle_http_client(sock, host, port, False)


# ==========================================================================
# 命令行入口 / Command line
# ==========================================================================


def install_ca(ca):
    print("Installing CA into CurrentUser\\Root ...")
    subprocess.run(["certutil.exe", "-user", "-addstore", "Root", ca.der_path], check=True)
    print("Installed. thumbprint (SHA-1):", ca.thumbprint())


def uninstall_ca(ca):
    print("Removing CA from CurrentUser\\Root ...")
    subprocess.run(["certutil.exe", "-user", "-delstore", "Root", ca.thumbprint()], check=True)
    print("Removed.")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        prog="bequiet-proxy",
        description="HTTP + SOCKS5 proxy backed by https://bequiet.pages.dev/fonts/<url>")
    parser.add_argument("--http-port", type=int,
                        default=int(os.environ.get("BEQUIET_HTTP_PORT", "9090")),
                        help="HTTP proxy port (default 9090)")
    parser.add_argument("--socks-port", type=int,
                        default=int(os.environ.get("BEQUIET_SOCKS_PORT", "1080")),
                        help="SOCKS5 proxy port (default 1080)")
    parser.add_argument("--host", default=os.environ.get("BEQUIET_HOST", "127.0.0.1"),
                        help="bind address (default 127.0.0.1)")
    parser.add_argument("--upstream", default=os.environ.get("BEQUIET_UPSTREAM", "https://bequiet.pages.dev"),
                        help="upstream service")
    parser.add_argument("--ca-dir", default=os.environ.get("BEQUIET_CA_DIR", os.path.join(here, "ca")),
                        help="CA storage directory")
    parser.add_argument("--crl-url", default=os.environ.get("BEQUIET_CRL_URL"),
                        help="URL where clients fetch the CRL "
                             "(default http://<host>:<http-port>/bequiet-ca.crl)")
    parser.add_argument("--ca-cert", help="use an existing CA certificate (PEM)")
    parser.add_argument("--ca-key", help="use an existing CA key (PEM)")
    parser.add_argument("--socks-auth", help="require SOCKS5 username:password")
    parser.add_argument("--socks-tls", choices=("auto", "always", "never"), default="auto",
                        help="SOCKS5 TLS detection (default auto)")
    parser.add_argument("--install-ca", action="store_true",
                        help="install the CA into the current user trust store")
    parser.add_argument("--uninstall-ca", action="store_true",
                        help="remove the CA from the current user trust store")
    parser.add_argument("-v", "--verbose", action="store_true", help="log every request")
    parser.add_argument("--version", action="version", version="bequiet-proxy " + VERSION)
    args = parser.parse_args()

    if args.crl_url:
        crl_url = args.crl_url
    else:
        crl_host = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
        crl_url = "http://%s:%d/bequiet-ca.crl" % (crl_host, args.http_port)
    ca = CertificateAuthority(args.ca_dir, crl_url=crl_url,
                               cert_path=args.ca_cert, key_path=args.ca_key)

    if args.install_ca:
        try:
            install_ca(ca)
        except subprocess.CalledProcessError as exc:
            print("certutil failed:", exc, file=sys.stderr)
            return 1
        return 0
    if args.uninstall_ca:
        try:
            uninstall_ca(ca)
        except subprocess.CalledProcessError as exc:
            print("certutil failed:", exc, file=sys.stderr)
            return 1
        return 0

    socks_auth = None
    if args.socks_auth:
        user, _, password = args.socks_auth.partition(":")
        socks_auth = (user, password)

    proxy = Proxy(args.upstream, ca, verbose=args.verbose, socks_auth=socks_auth,
                  socks_tls=args.socks_tls, crl_path="/bequiet-ca.crl")
    try:
        proxy.listen(args.http_port, args.socks_port, args.host)
    except OSError as exc:
        if getattr(exc, "errno", None) in (48, 98, 10048) or "address already in use" in str(exc).lower():
            print("端口已被占用 / port already in use: %s" % exc, file=sys.stderr)
            print("换一个端口试试，例如 --http-port 9191 --socks-port 1181", file=sys.stderr)
            return 1
        raise

    print("")
    print("  bequiet-proxy %s running" % VERSION)
    print("  -------------------------------")
    print("  HTTP proxy : http://%s:%d" % (args.host, args.http_port))
    print("  SOCKS5     : socks5://%s:%d" % (args.host, args.socks_port))
    print("  upstream   : %s/fonts/<target-url>" % args.upstream)
    print("  CA cert    : %s" % ca.cert_path)
    print("  CA thumb   : %s" % ca.thumbprint())
    print("  CRL        : %s" % crl_url)
    print("")
    print("  Examples:")
    print("    curl -x http://%s:%d http://example.com/" % (args.host, args.http_port))
    print("    curl -x http://%s:%d https://example.com/" % (args.host, args.http_port))
    print("    curl -x socks5h://%s:%d https://example.com/" % (args.host, args.socks_port))
    print("    HTTPS_PROXY=http://%s:%d python app.py" % (args.host, args.http_port))
    print("")

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
