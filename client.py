# DNS security client
# DNS security client

import json
import secrets
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dnssec_crypto import (
    canonical_record,
    public_key_fingerprint,
    public_key_from_base64,
    verify_signature,
)


HOST = "127.0.0.1"
PORT = 53535
TRUST_ANCHOR_FILE = Path("trust_anchor.txt")


def normalize_name(name):
    """Normalize a DNS name for consistent comparisons."""
    return name.lower().rstrip(".")


def load_trust_anchor():
    """Load the trusted public-key fingerprint."""
    if not TRUST_ANCHOR_FILE.exists():
        raise FileNotFoundError(
            "trust_anchor.txt was not found. "
            "Create it with the trusted key fingerprint."
        )

    fingerprint = TRUST_ANCHOR_FILE.read_text(
        encoding="utf-8"
    ).strip().lower()

    if not fingerprint:
        raise ValueError("trust_anchor.txt is empty.")

    return fingerprint


def is_within_validity_period(inception, expiration):
    """Check whether the response is currently valid."""
    try:
        current_time = datetime.now(timezone.utc)
        start_time = datetime.fromisoformat(inception)
        end_time = datetime.fromisoformat(expiration)

        return start_time <= current_time <= end_time

    except ValueError:
        return False


def validate_response(response, query, trusted_key_id):
    """Validate a DNS response before accepting its IP address."""
    if response.get("type") != "DNS_RESPONSE":
        return False, "Invalid response type."

    if response.get("status") != "SUCCESS":
        return False, response.get("error", "The server returned an error.")

    if response.get("transaction_id") != query.get("transaction_id"):
        return False, "Transaction ID does not match."

    if response.get("nonce") != query.get("nonce"):
        return False, "Nonce does not match."

    if normalize_name(response.get("name", "")) != normalize_name(
        query.get("name", "")
    ):
        return False, "Domain name does not match the query."

    if response.get("record_type") != query.get("record_type"):
        return False, "Record type does not match the query."

    required_fields = [
        "address",
        "ttl",
        "inception",
        "expiration",
        "key_id",
        "public_key",
        "signature",
    ]

    for field in required_fields:
        if field not in response:
            return False, f"Missing response field: {field}"

    if response["key_id"] != trusted_key_id:
        return False, "The response key does not match the trust anchor."

    try:
        public_key = public_key_from_base64(response["public_key"])
    except Exception:
        return False, "The public key could not be decoded."

    calculated_key_id = public_key_fingerprint(public_key)

    if calculated_key_id != trusted_key_id:
        return False, "The public-key fingerprint is not trusted."

    if not is_within_validity_period(
        response["inception"],
        response["expiration"],
    ):
        return False, "The DNS response is expired or not yet valid."

    signed_data = canonical_record(
        name=normalize_name(response["name"]),
        record_type=response["record_type"],
        address=response["address"],
        ttl=response["ttl"],
        key_id=response["key_id"],
        inception=response["inception"],
        expiration=response["expiration"],
        transaction_id=response["transaction_id"],
        nonce=response["nonce"],
    )

    if not verify_signature(
        public_key,
        signed_data,
        response["signature"],
    ):
        return False, "Digital signature verification failed."

    return True, "The DNS response passed all validation checks."


def create_query(name, record_type):
    """Create a DNS query with a transaction ID and nonce."""
    return {
        "type": "DNS_QUERY",
        "transaction_id": uuid.uuid4().hex,
        "name": normalize_name(name),
        "record_type": record_type.upper(),
        "nonce": secrets.token_urlsafe(16),
    }


def send_query(query):
    """Send a query to the DNS server and receive its response."""
    with socket.create_connection((HOST, PORT), timeout=10) as connection:
        input_stream = connection.makefile(
            "r",
            encoding="utf-8",
        )
        output_stream = connection.makefile(
            "w",
            encoding="utf-8",
        )

        output_stream.write(json.dumps(query) + "\n")
        output_stream.flush()

        response_line = input_stream.readline()

        if not response_line:
            raise ConnectionError("The server closed the connection.")

        return json.loads(response_line)


def main():
    print("DNS Security Client")

    try:
        trusted_key_id = load_trust_anchor()
    except (FileNotFoundError, ValueError) as error:
        print(f"Trust-anchor error: {error}")
        return

    name = input("Enter a domain name: ").strip()
    record_type = input("Enter record type [A]: ").strip() or "A"

    query = create_query(name, record_type)

    print(f"Sending query for {query['name']}...")

    try:
        response = send_query(query)
    except Exception as error:
        print(f"Connection error: {error}")
        return

    valid, message = validate_response(
        response,
        query,
        trusted_key_id,
    )

    if not valid:
        print(f"REJECTED: {message}")
        return

    print(f"ACCEPTED: {message}")
    print(f"Address: {response['address']}")
    print(f"TTL: {response['ttl']} seconds")


if __name__ == "__main__":
    main()