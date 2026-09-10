"""Minimales WebAuthn (FIDO2) ohne Fremdbibliothek: Registrierung und Anmeldung mit ES256.

Nur was das Notariat braucht: eine Kennung (der YubiKey), Attestation "none", Prüfung von
rpIdHash, Flags (User Present, User Verified), Zähler und Signatur.
"""
import hashlib, base64, struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

def b64url_decode(s):
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# ---- CBOR (nur die Teilmenge, die Authenticator-Daten verwenden) ----
def cbor_decode(data):
    val, _ = _cbor(data, 0)
    return val

def _cbor(d, i):
    ib = d[i]; mt, ai = ib >> 5, ib & 0x1f; i += 1
    if ai < 24: n = ai
    elif ai == 24: n = d[i]; i += 1
    elif ai == 25: n = struct.unpack(">H", d[i:i+2])[0]; i += 2
    elif ai == 26: n = struct.unpack(">I", d[i:i+4])[0]; i += 4
    elif ai == 27: n = struct.unpack(">Q", d[i:i+8])[0]; i += 8
    else: raise ValueError("CBOR: unsupported length")
    if mt == 0: return n, i
    if mt == 1: return -1 - n, i
    if mt == 2: return d[i:i+n], i + n
    if mt == 3: return d[i:i+n].decode(), i + n
    if mt == 4:
        out = []
        for _ in range(n): v, i = _cbor(d, i); out.append(v)
        return out, i
    if mt == 5:
        out = {}
        for _ in range(n):
            k, i = _cbor(d, i); v, i = _cbor(d, i); out[k] = v
        return out, i
    if mt == 7 and ai in (20, 21): return ai == 21, i
    if mt == 7 and ai == 22: return None, i
    raise ValueError("CBOR: unsupported type")

def parse_auth_data(ad):
    rp_id_hash, flags, counter = ad[:32], ad[32], struct.unpack(">I", ad[33:37])[0]
    out = {"rpIdHash": rp_id_hash, "up": bool(flags & 1), "uv": bool(flags & 4), "at": bool(flags & 64), "counter": counter}
    if out["at"]:
        i = 37 + 16
        cid_len = struct.unpack(">H", ad[i:i+2])[0]; i += 2
        out["credId"] = ad[i:i+cid_len]; i += cid_len
        out["cose"] = cbor_decode(ad[i:])
    return out

def cose_to_public_key(cose):
    # ES256: kty=2 (EC2), alg=-7, crv=1 (P-256), x=-2, y=-3
    if cose.get(1) != 2 or cose.get(3) != -7 or cose.get(-1) != 1:
        raise ValueError("Nur ES256 auf P-256 wird unterstützt")
    return ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1()).public_key()

def public_key_hex(pub):
    from cryptography.hazmat.primitives import serialization
    return pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()

def public_key_from_hex(h):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(h))

def registrierung_pruefen(rp_id, challenge, origin, client_data_b64, attestation_b64):
    """Gibt (credId, public_key_hex, counter) zurück oder wirft ValueError."""
    import json
    cd = json.loads(b64url_decode(client_data_b64))
    if cd.get("type") != "webauthn.create": raise ValueError("Falscher Typ")
    if cd.get("challenge") != challenge: raise ValueError("Challenge stimmt nicht")
    if cd.get("origin") != origin: raise ValueError("Origin stimmt nicht")
    att = cbor_decode(b64url_decode(attestation_b64))
    ad = parse_auth_data(att["authData"])
    if ad["rpIdHash"] != hashlib.sha256(rp_id.encode()).digest(): raise ValueError("rpId stimmt nicht")
    if not ad["up"] or not ad["uv"]: raise ValueError("Nutzer nicht anwesend oder nicht verifiziert (PIN am YubiKey nötig)")
    if not ad["at"]: raise ValueError("Keine Kennungsdaten")
    pub = cose_to_public_key(ad["cose"])
    return b64url_encode(ad["credId"]), public_key_hex(pub), ad["counter"]

def anmeldung_pruefen(rp_id, challenge, origin, public_key_hex_, stored_counter, client_data_b64, auth_data_b64, signature_b64):
    """Gibt den neuen Zähler zurück oder wirft ValueError."""
    import json
    cd_raw = b64url_decode(client_data_b64)
    cd = json.loads(cd_raw)
    if cd.get("type") != "webauthn.get": raise ValueError("Falscher Typ")
    if cd.get("challenge") != challenge: raise ValueError("Challenge stimmt nicht")
    if cd.get("origin") != origin: raise ValueError("Origin stimmt nicht")
    ad_raw = b64url_decode(auth_data_b64)
    ad = parse_auth_data(ad_raw)
    if ad["rpIdHash"] != hashlib.sha256(rp_id.encode()).digest(): raise ValueError("rpId stimmt nicht")
    if not ad["up"] or not ad["uv"]: raise ValueError("Nutzer nicht anwesend oder nicht verifiziert")
    if ad["counter"] != 0 and ad["counter"] <= stored_counter: raise ValueError("Zähler nicht gestiegen, möglicher Klon")
    pub = public_key_from_hex(public_key_hex_)
    signed = ad_raw + hashlib.sha256(cd_raw).digest()
    try:
        pub.verify(b64url_decode(signature_b64), signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError("Signatur ungültig")
    return ad["counter"]
