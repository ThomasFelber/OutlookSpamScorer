"""Verschlüsselung der Fragebögen.

Hybrid: X25519 (Schlüsselaustausch) + HKDF-SHA256 + AES-256-GCM.
Der Server kennt nur den öffentlichen Schlüssel des Notariats. Der private Schlüssel
bleibt im Büro. Ein Angreifer mit Zugriff auf Server und Datenbank kann nichts lesen.
"""
import os, base64, json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

INFO = b"notariat-fragebogen-v1"

def neues_schluesselpaar():
    priv = X25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization as s
    priv_raw = priv.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    pub_raw = priv.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    return priv_raw.hex(), pub_raw.hex()

def _key(shared):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(shared)

def verschluesseln(pub_hex, klartext: bytes, aad: bytes) -> dict:
    pub = X25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    eph = X25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization as s
    eph_pub = eph.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    key = _key(eph.exchange(pub))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, klartext, aad)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"eph": b64(eph_pub), "nonce": b64(nonce), "ct": b64(ct)}

def entschluesseln(priv_hex, paket: dict, aad: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    b = lambda k: base64.b64decode(paket[k])
    eph_pub = X25519PublicKey.from_public_bytes(b("eph"))
    key = _key(priv.exchange(eph_pub))
    return AESGCM(key).decrypt(b("nonce"), b("ct"), aad)
