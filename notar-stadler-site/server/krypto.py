"""Verschlüsselung der Eingänge.

Hybrid: ECDH auf P-256 (Schlüsselaustausch) + HKDF-SHA256 + AES-256-GCM.
P-256, damit der Browser des Notariats (WebCrypto) ohne Zusatzbibliothek entschlüsseln kann.
Der Server kennt nur den öffentlichen Schlüssel. Der private Schlüssel liegt, mit YubiKey und
Passwort gesichert, nur im Browser des Notariats und als Sicherungskopie im Büro.

Formate: öffentlicher Schlüssel = unkomprimierter Punkt, 65 Byte, hex.
         privater Schlüssel     = Skalar, 32 Byte, hex.
"""
import os, base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

INFO = b"notariat-fragebogen-v2"
CURVE = ec.SECP256R1()

def _pub_bytes(pub):
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

def neues_schluesselpaar():
    priv = ec.generate_private_key(CURVE)
    return priv.private_numbers().private_value.to_bytes(32, "big").hex(), _pub_bytes(priv.public_key()).hex()

def _key(shared):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(shared)

def verschluesseln(pub_hex, klartext: bytes, aad: bytes) -> dict:
    pub = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, bytes.fromhex(pub_hex))
    eph = ec.generate_private_key(CURVE)
    key = _key(eph.exchange(ec.ECDH(), pub))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, klartext, aad)
    b64 = lambda b: base64.b64encode(b).decode()
    return {"eph": b64(_pub_bytes(eph.public_key())), "nonce": b64(nonce), "ct": b64(ct)}

def entschluesseln(priv_hex, paket: dict, aad: bytes) -> bytes:
    priv = ec.derive_private_key(int(priv_hex, 16), CURVE)
    b = lambda k: base64.b64decode(paket[k])
    eph = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, b("eph"))
    key = _key(priv.exchange(ec.ECDH(), eph))
    return AESGCM(key).decrypt(b("nonce"), b("ct"), aad)

# ---- Referenznummer: 6 Zeichen, ohne 0/O, 1/I/L ----
REF_ZEICHEN = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

def neue_referenz():
    import secrets
    return "".join(secrets.choice(REF_ZEICHEN) for _ in range(6))

def referenz_normalisieren(s):
    s = (s or "").strip().upper().replace("-", "").replace(" ", "")
    return s.replace("0", "O").replace("1", "I").replace("L", "I") if False else s
