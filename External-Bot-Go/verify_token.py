import sys
import time
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def b64url_decode(s: str) -> bytes:
    # Add back the padding that Discord strips out
    padded = s + '=' * (-len(s) % 4)
    # Convert URL-safe characters back to standard base64
    padded = padded.replace('-', '+').replace('_', '/')
    return base64.b64decode(padded)

def verify_token(token: str, root_pub_path: str):
    print(f"\n🔍 Testing token: {token[:20]}...{token[-10:]}\n")

    # 1. Load Root Public Key
    try:
        with open(root_pub_path, "rb") as f:
            root_public_key = serialization.load_pem_public_key(f.read())
    except Exception as e:
        print(f"❌ Error loading root public key from {root_pub_path}: {e}")
        sys.exit(1)

    if not isinstance(root_public_key, Ed25519PublicKey):
        print("❌ Error: Root public key must be an Ed25519 key.")
        sys.exit(1)

    # 2. Split Token (Now 4 parts)
    parts = token.split(".")
    if len(parts) != 4:
        print(f"❌ INVALID: Token format is wrong. Expected 4 parts, got {len(parts)}.")
        sys.exit(1)
    
    payload_b64, sig_b64, int_pub_b64, cert_b64 = parts

    # 3. Decode Base64
    try:
        payload_bytes = b64url_decode(payload_b64)
        sig_bytes = b64url_decode(sig_b64)
        int_pub_bytes = b64url_decode(int_pub_b64)
        cert_bytes = b64url_decode(cert_b64)
    except Exception as e:
        print(f"❌ INVALID: Could not decode base64 string. ({e})")
        sys.exit(1)

    # 4. Verify Root Signature (The Certificate)
    try:
        # The certificate is a signature of the intermediate public key
        root_public_key.verify(cert_bytes, int_pub_bytes)
        print("✅ Certificate: VALID (Intermediate key is trusted)")
    except InvalidSignature:
        print("❌ Certificate: INVALID (Untrusted intermediate key!)")
        sys.exit(1)

    # 5. Load Intermediate Public Key from the token
    try:
        intermediate_pub = Ed25519PublicKey.from_public_bytes(int_pub_bytes)
    except Exception as e:
        print(f"❌ INVALID: Could not load intermediate public key. ({e})")
        sys.exit(1)

    # 6. Verify Token Signature using Intermediate Key
    try:
        intermediate_pub.verify(sig_bytes, payload_bytes)
        print("✅ Signature:   VALID (Signed by verified intermediate key)")
    except InvalidSignature:
        print("❌ Signature:   INVALID (Forged or tampered token)")
        sys.exit(1)

    # 7. Parse Payload
    try:
        payload = json.loads(payload_bytes)
        exp = payload.get("exp", 0)
        iat = payload.get("iat", 0)
        print(f"✅ Payload:     VALID JSON (Issued: {time.strftime('%H:%M:%S', time.localtime(iat))})")
    except Exception as e:
        print(f"❌ INVALID: Could not parse JSON payload. ({e})")
        sys.exit(1)

    # 8. Check Expiry
    now = int(time.time())
    if now > exp + 60:
        print(f"❌ Expiry:      EXPIRED (Expired {(now - exp)} seconds ago)")
        sys.exit(1)
    else:
        remaining = exp - now
        m, s = divmod(remaining, 60)
        print(f"✅ Expiry:      VALID (Expires in {m}m {s:02d}s)")

    print("\n🎉 SUCCESS: The token is completely valid and would be accepted by the client.\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_token.py <YOUR_TOKEN_HERE>")
        sys.exit(1)
    
    # Get the token from the command line argument
    token_str = sys.argv[1].strip()
    
    # Look for the ROOT public key in the current directory's 'keys' folder
    key_path = Path(__file__).parent / "keys" / "root_public.pem"
    
    verify_token(token_str, str(key_path))