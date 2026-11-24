# DNSSEC cryptography module

# Shared by server.py and client.py. Handles key generation and loading,
# key fingerprints (the trust anchor), the canonical record format, and
# RSA-PSS signing and verification with SHA-256.

import base64
import binascii
import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEY_DIR = Path("keys")
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
TRUST_ANCHOR_FILE = Path("trust_anchor.txt")

KEY_SIZE = 2048
FIELD_SEPARATOR = "|"

# RSA-PSS padding with SHA-256, used for both signing and verifying.
PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)

# Key generation and loading

def generate_key_pair():
    """Generate a new RSA key pair in memory."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
    )
    return private_key, private_key.public_key()


def save_private_key(private_key, path):
    """Save a private key to a PEM file."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    Path(path).write_bytes(pem)


def save_public_key(public_key, path):
    """Save a public key to a PEM file."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(path).write_bytes(pem)


def load_private_key(path):
    """Load a private key from a PEM file."""
    return serialization.load_pem_private_key(
        Path(path).read_bytes(),
        password=None,
    )


def load_public_key(path):
    """Load a public key from a PEM file."""
    return serialization.load_pem_public_key(Path(path).read_bytes())


def write_trust_anchor(public_key, path=TRUST_ANCHOR_FILE):
    """Write the public-key fingerprint to the trust-anchor file."""
    Path(path).write_text(
        public_key_fingerprint(public_key) + "\n",
        encoding="utf-8",
    )


def generate_or_load_keys(key_dir=KEY_DIR, trust_anchor_file=TRUST_ANCHOR_FILE):
    """
    Load the server's signing keys, or create them on the first run.

    Also writes the trust-anchor file so the client knows which public
    key to trust. The private key never leaves the key directory.
    """
    key_dir = Path(key_dir)
    private_path = key_dir / PRIVATE_KEY_FILE
    public_path = key_dir / PUBLIC_KEY_FILE

    if private_path.exists():
        private_key = load_private_key(private_path)
        public_key = private_key.public_key()
    else:
        key_dir.mkdir(parents=True, exist_ok=True)
        private_key, public_key = generate_key_pair()
        save_private_key(private_key, private_path)

    save_public_key(public_key, public_path)
    write_trust_anchor(public_key, trust_anchor_file)

    return private_key, public_key


# Key encoding and fingerprints

def public_key_der(public_key):
    """Return the public key in DER (binary) form."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_fingerprint(public_key):
    """
    Return the key identifier: the SHA-256 hash of the DER public key,
    as lowercase hex. This value is the client's trust anchor.
    """
    return hashlib.sha256(public_key_der(public_key)).hexdigest()


def public_key_to_base64(public_key):
    """Encode a public key as base64 text for a JSON response."""
    return base64.b64encode(public_key_der(public_key)).decode("ascii")


def public_key_from_base64(encoded_key):
    """
    Decode a base64 public key from a JSON response.

    Raises ValueError if the data is not a valid RSA public key of at
    least 2048 bits.
    """
    try:
        der = base64.b64decode(encoded_key, validate=True)
    except (binascii.Error, TypeError) as error:
        raise ValueError("Public key is not valid base64.") from error

    public_key = serialization.load_der_public_key(der)

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("Public key is not an RSA key.")

    if public_key.key_size < KEY_SIZE:
        raise ValueError("Public key is smaller than 2048 bits.")

    return public_key


# Canonical record format

def _escape_field(value):
    """
    Escape backslashes and separators so that no field can contain an
    unescaped "|". This keeps the format unambiguous: two different sets
    of fields can never produce the same canonical string.
    """
    text = str(value)
    text = text.replace("\\", "\\\\")
    text = text.replace(FIELD_SEPARATOR, "\\" + FIELD_SEPARATOR)
    return text


def canonical_record(
    name,
    record_type,
    address,
    ttl,
    key_id,
    inception,
    expiration,
    transaction_id,
    nonce,
):
    """
    Build the exact bytes that get signed.

    Format (fields joined with "|", UTF-8 encoded):
        name|record_type|address|ttl|key_id|inception|expiration|transaction_id|nonce

    The name is lowercased with any trailing dot removed, and the record
    type is uppercased, so both sides always build identical bytes.
    """
    fields = [
        str(name).lower().rstrip("."),
        str(record_type).upper(),
        address,
        ttl,
        key_id,
        inception,
        expiration,
        transaction_id,
        nonce,
    ]
    return FIELD_SEPARATOR.join(
        _escape_field(field) for field in fields
    ).encode("utf-8")


# Signing and verification

def sha256_hex(data):
    """Return the SHA-256 digest of some bytes as hex (useful for logs)."""
    return hashlib.sha256(data).hexdigest()


def sign_record(private_key, data):
    """
    Sign canonical record bytes with RSA-PSS and SHA-256.
    Returns the signature as base64 text.
    """
    signature = private_key.sign(data, PSS_PADDING, hashes.SHA256())
    return base64.b64encode(signature).decode("ascii")


def verify_signature(public_key, data, signature_b64):
    """
    Verify a base64 signature over canonical record bytes.
    Returns True only if the signature is valid. Never raises.
    """
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, data, PSS_PADDING, hashes.SHA256())
        return True
    except (InvalidSignature, binascii.Error, ValueError, TypeError):
        return False