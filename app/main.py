from fastapi import FastAPI, HTTPException
from pathlib import Path
from cryptography.hazmat.primitives import serialization
import time

from scripts.crypto_utils import (
    decrypt_seed,
    generate_totp_code,
    verify_totp_code
)

app = FastAPI()

# Path where seed is stored (Docker volume)
SEED_FILE = Path("/data/seed.txt")

# Load student private key
with open("student_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# --------------------------------------------------
# ENDPOINT 1: POST /decrypt-seed
# --------------------------------------------------
@app.post("/decrypt-seed")
def decrypt_seed_api(payload: dict):
    if "encrypted_seed" not in payload:
        raise HTTPException(status_code=400, detail="Missing encrypted_seed")

    try:
        # Decrypt encrypted seed
        seed = decrypt_seed(payload["encrypted_seed"], private_key)

        # Create /data directory if not exists
        SEED_FILE.parent.mkdir(parents=True, exist_ok=True)

        # Save decrypted seed
        SEED_FILE.write_text(seed)

        return {"status": "ok"}

    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed")


# --------------------------------------------------
# ENDPOINT 2: GET /generate-2fa
# --------------------------------------------------
@app.get("/generate-2fa")
def generate_2fa():
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    # Read hex seed
    hex_seed = SEED_FILE.read_text().strip()

    # Generate TOTP code
    code = generate_totp_code(hex_seed)

    # Calculate remaining seconds (0–29)
    valid_for = 30 - (int(time.time()) % 30)

    return {
        "code": code,
        "valid_for": valid_for
    }


# --------------------------------------------------
# ENDPOINT 3: POST /verify-2fa
# --------------------------------------------------
@app.post("/verify-2fa")
def verify_2fa(payload: dict):
    if "code" not in payload:
        raise HTTPException(status_code=400, detail="Missing code")

    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    # Read hex seed
    hex_seed = SEED_FILE.read_text().strip()

    # Verify TOTP code (±30 seconds)
    is_valid = verify_totp_code(hex_seed, payload["code"])

    return {"valid": is_valid}