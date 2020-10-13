import util
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend as default_backend

def create_rsa_private_key():
    private_key = rsa.generate_private_key(
        backend=default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    return private_key

def get_jwk_from_public_key(public_key):
    e = public_key.public_numbers().e
    n = public_key.public_numbers().n
    e = util.to_base64(util.int_to_bytes(e))
    n = util.to_base64(util.int_to_bytes(n))
    my_jwk = {
        "kty": "RSA",
        "n": n,
        "e": e
    }
    return my_jwk

def get_jws(protected_header, payload, private_key):
    protected_header = util.to_base64(json.dumps(protected_header))
    payload = util.to_base64(json.dumps(payload))
    message = protected_header + "." + payload
    signature = private_key.sign(
        message.encode('utf8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature = util.to_base64(signature)
    jws = {}
    jws["protected"] = protected_header
    jws["payload"] = payload
    jws["signature"] = signature
    jws = json.dumps(jws).encode("utf8")
    return jws

def write_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)
        f.close()

def write_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as f:
        f.write(pem)
        f.close()

def load_private_key(filename):
    with open(filename, "rb") as f:
        private = serialization.load_pem_private_key(
            f.read(), None, backend=default_backend()
        )
        f.close()
    return private