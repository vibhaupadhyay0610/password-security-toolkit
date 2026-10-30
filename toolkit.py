"""Password security toolkit: strength check, secure generation, salted PBKDF2 hashing."""
import hashlib, hmac, math, os, re, secrets, string

def entropy_bits(password: str) -> float:
    pool = 0
    pool += 26 if re.search(r"[a-z]", password) else 0
    pool += 26 if re.search(r"[A-Z]", password) else 0
    pool += 10 if re.search(r"\d", password) else 0
    pool += 32 if re.search(r"[^\w\s]", password) else 0
    return len(password) * math.log2(pool) if pool else 0.0

def strength(password: str) -> str:
    bits = entropy_bits(password)
    if bits < 40: return "Weak"
    if bits < 60: return "Moderate"
    if bits < 80: return "Strong"
    return "Very strong"

def generate(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))

def hash_password(password: str, iterations: int = 200_000):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return salt.hex(), digest.hex()

def verify(password: str, salt_hex: str, digest_hex: str, iterations: int = 200_000) -> bool:
    new = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), iterations)
    return hmac.compare_digest(new.hex(), digest_hex)

if __name__ == "__main__":
    for pw in ["password", "Trinity2026", generate()]:
        print(f"{pw:<20} {entropy_bits(pw):6.1f} bits  {strength(pw)}")
    salt, digest = hash_password("MyS3cret!")
    print("Verify correct:", verify("MyS3cret!", salt, digest))
    print("Verify wrong  :", verify("guess", salt, digest))
