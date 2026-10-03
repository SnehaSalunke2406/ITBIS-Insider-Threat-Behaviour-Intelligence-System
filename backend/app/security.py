import base64, hashlib, hmac, json, time
from .config import JWT_SECRET, JWT_EXPIRES_MINUTES


def hash_password(password: str) -> str:
    salt = hashlib.sha256((password + "|itbis-salt").encode()).digest()[:16]
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return "pbkdf2$120000$" + base64.urlsafe_b64encode(salt).decode() + "$" + base64.urlsafe_b64encode(dk).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        _, rounds, salt64, digest64 = stored.split("$", 3)
        salt = base64.urlsafe_b64decode(salt64.encode())
        expected = base64.urlsafe_b64decode(digest64.encode())
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _ub64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def create_token(user_id: int, email: str, role: str) -> str:
    header = _b64(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(",", ":")).encode())
    payload = _b64(json.dumps({"sub":str(user_id),"email":email,"role":role,"exp":int(time.time()) + JWT_EXPIRES_MINUTES*60}, separators=(",", ":")).encode())
    unsigned = header + "." + payload
    sig = _b64(hmac.new(JWT_SECRET.encode(), unsigned.encode(), hashlib.sha256).digest())
    return unsigned + "." + sig


def decode_token(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token")
    unsigned = parts[0] + "." + parts[1]
    expected = _b64(hmac.new(JWT_SECRET.encode(), unsigned.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, parts[2]):
        raise ValueError("Invalid signature")
    payload = json.loads(_ub64(parts[1]).decode())
    if int(payload["exp"]) < int(time.time()):
        raise ValueError("Token expired")
    return payload
