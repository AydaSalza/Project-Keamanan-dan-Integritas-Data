# ===========================================
# File Client Lengkap
# ===========================================

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import hashes, serialization
import base64

# ===========================================
# 1️⃣ Pinkkan - Load private key ECDSA
# ===========================================
private_key_pem = b"""
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgJLwFpa/JSHW5d9dMNJAL
Co3JJKt2l/VEnKYztHjAENGhRANCAAQOxXHl4D6Q9yzTCkf9PPtiAYMUT0Ie3feG
NkJAK6WCi0RpiGkRg/N0Qnq0NiT9BVkqsbGgm9lD0XwaqFilV0zF
-----END PRIVATE KEY-----
"""

priv_key = serialization.load_pem_private_key(
    private_key_pem,
    password=None
)

# Public key
pub_key = priv_key.public_key()
with open("pinkkan_public_key.pem", "wb") as f:
    f.write(pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Pesan yang akan ditandatangani
message = b"hello world"
message_b64 = base64.b64encode(message).decode().replace("\n","")

# Signature ECDSA base64
signature = priv_key.sign(message, ec.ECDSA(hashes.SHA256()))
signature_b64 = base64.b64encode(signature).decode().replace("\n","")

print("Pinkkan message (base64):", message_b64)
print("Pinkkan signature (base64):", signature_b64)

# ===========================================
# 2️⃣ Grace - Load private key Ed25519
# ===========================================
private_key_pem_grace = b"""
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKD+bs5bKthPtn5fYXc47CcLCdxwFVDi+/uqPp+qquDZ
-----END PRIVATE KEY-----
"""

priv_key_grace = serialization.load_pem_private_key(
    private_key_pem_grace,
    password=None
)

assert isinstance(priv_key_grace, ed25519.Ed25519PrivateKey), "Key bukan Ed25519!"

pub_key_grace = priv_key_grace.public_key()
with open("grace_public_key.pem", "wb") as f:
    f.write(pub_key_grace.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

message_grace = b"hello from grace"
message_grace_b64 = base64.b64encode(message_grace).decode().replace("\n","")

signature_grace = priv_key_grace.sign(message_grace)
signature_grace_b64 = base64.b64encode(signature_grace).decode().replace("\n","")

print("Grace message (base64):", message_grace_b64)
print("Grace signature (base64):", signature_grace_b64)

# ===========================================
# 3️⃣ Tandatangan PDF
# ===========================================
pdf_file = "Dummy.pdf"  # nama PDF
with open(pdf_file, "rb") as f:
    pdf_bytes = f.read()

# ================= HASH PDF =================
digest = hashes.Hash(hashes.SHA256())
digest.update(pdf_bytes)
pdf_hash = digest.finalize()

# Base64 PDF (optional, kalau mau dikirim ke server)
pdf_b64 = base64.b64encode(pdf_bytes).decode()
print("Message (base64 PDF) siap dikirim:", pdf_b64)

# ================= SIGN HASH PDF =================

# Pinkkan (ECDSA)
pdf_sig_pinkkan = priv_key.sign(
    pdf_hash,
    ec.ECDSA(hashes.SHA256())
)
pdf_sig_pinkkan_b64 = base64.b64encode(pdf_sig_pinkkan).decode()
print("Signature Pinkkan (base64 PDF):", pdf_sig_pinkkan_b64)

# Grace (Ed25519)
pdf_sig_grace = priv_key_grace.sign(pdf_hash)
pdf_sig_grace_b64 = base64.b64encode(pdf_sig_grace).decode()
print("Signature Grace (base64 PDF):", pdf_sig_grace_b64)
