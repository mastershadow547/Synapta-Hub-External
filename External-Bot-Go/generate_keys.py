"""Generate Root and Intermediate Ed25519 keys for the token bot.

- Root keys: Keep offline. The public key goes into your C++ client.
- Intermediate keys: Upload to the server. These sign the tokens.
- Certificate: Root signs the Intermediate public key. Upload to the server.
"""

import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

out_dir = Path(__file__).parent / "keys"
out_dir.mkdir(parents=True, exist_ok=True)

def save_priv(key, path):
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

def save_pub(key, path):
    path.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

def get_raw_pub(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def fingerprint(path: Path) -> str:
    if not path.exists():
        return "(none)"
    return hashlib.sha256(path.read_bytes()).hexdigest()

# 1. Generate Root Keys (Permanent, goes into C++ Client)
root_priv = Ed25519PrivateKey.generate()
save_priv(root_priv, out_dir / "root_private.pem")
save_pub(root_priv, out_dir / "root_public.pem")

# 2. Generate Intermediate Keys (Rotatable, goes into Go Bot)
int_priv = Ed25519PrivateKey.generate()
save_priv(int_priv, out_dir / "intermediate_private.pem")
save_pub(int_priv, out_dir / "intermediate_public.pem")

# 3. Create Certificate (Root signs Intermediate)
int_pub_raw = get_raw_pub(int_priv)
cert = root_priv.sign(int_pub_raw)
(out_dir / "intermediate_cert.bin").write_bytes(cert)

# 4. Output
root_pub_pem = (out_dir / "root_public.pem").read_text()

print("═" * 64)
print("  Key Generation Complete (Root + Intermediate)")
print("═" * 64)
print(f"  Root Private:         {fingerprint(out_dir / 'root_private.pem')}")
print(f"  Intermediate Private: {fingerprint(out_dir / 'intermediate_private.pem')}")
print()
print("  ⚠️  IMPORTANT NEXT STEPS:")
print("  1. Keep 'keys/root_private.pem' safe and OFFLINE. Never upload it.")
print("  2. Upload these three files to Waifly:")
print("     - intermediate_private.pem")
print("     - intermediate_public.pem (optional, but good for reference)")
print("     - intermediate_cert.bin")
print("  3. Paste the ROOT public key below into client/embedded_public_key.h")
print()
print("  --- ROOT PUBLIC KEY ---")
print(root_pub_pem)
print("  -----------------------")
print("═" * 64)