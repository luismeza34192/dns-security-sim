# DNS security server

import argparse
import base64
import json
import logging
import socket
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dnssec_crypto import (
    canonical_record,
    generate_key_pair,
    generate_or_load_keys,
    public_key_fingerprint,
    public_key_to_base64,
    sign_record,
)


HOST = "127.0.0.1"
PORT = 53535
RECORDS_FILE = Path("records.json")
TTL_SECONDS = 300

# Fields covered by the digital signature, in standard order
SIGNED_FIELDS = [
    "name",
    "record_type",
    "address",
    "ttl",
    "key_id",
    "inception",
    "expiration",
    "transaction_id",
    "nonce",
]

# Fields used only for routing or processing, not signed
UNSIGNED_FIELDS = ["type", "status", "public_key", "signature"]

# Attack modes for the security demonstrations
# Each one simulates an attacker sitting between the server and the client
ATTACK_MODES = {
    "tamper": "Change the IP address after the response is signed",
    "badsig": "Corrupt one byte of the signature",
    "wrongkey": "Re-sign a fake address with an attacker key and send that key",
    "keyspoof": "Send the attacker key but keep the trusted key ID",
    "expired": "Send a correctly signed response whose validity period has ended",
    "replay": "Capture the first response, then resend it to later queries",
}

FAKE_ADDRESS = "10.0.0.66"


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(message)s",
)


def load_records():
    """Load DNS records from records.json."""
    with RECORDS_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def utc_now():
    """Return the current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def make_error_response(query, message):
    """Create an unsigned error response."""
    return {
        "type": "DNS_RESPONSE",
        "status": "ERROR",
        "transaction_id": query.get("transaction_id"),
        "nonce": query.get("nonce"),
        "name": query.get("name"),
        "record_type": query.get("record_type"),
        "error": message,
    }


def create_signed_response(query, records, private_key, public_key, key_id):
    """Process a DNS query and create a signed response."""
    if query.get("type") != "DNS_QUERY":
        return make_error_response(query, "Invalid message type")

    required_fields = [
        "transaction_id",
        "name",
        "record_type",
        "nonce",
    ]

    missing_fields = [
        field for field in required_fields if not query.get(field)
    ]

    if missing_fields:
        return make_error_response(
            query,
            f"Missing fields: {', '.join(missing_fields)}",
        )

    name = query["name"].lower().rstrip(".")
    record_type = query["record_type"].upper()
    transaction_id = query["transaction_id"]
    nonce = query["nonce"]

    if name not in records:
        return make_error_response(
            query,
            f"Unknown domain name: {name}",
        )

    if record_type not in records[name]:
        return make_error_response(
            query,
            f"Unsupported record type: {record_type}",
        )

    address = records[name][record_type]
    inception = utc_now()
    expiration = (
        datetime.now(timezone.utc) + timedelta(seconds=TTL_SECONDS)
    ).isoformat()

    signed_data = canonical_record(
        name=name,
        record_type=record_type,
        address=address,
        ttl=TTL_SECONDS,
        key_id=key_id,
        inception=inception,
        expiration=expiration,
        transaction_id=transaction_id,
        nonce=nonce,
    )

    signature = sign_record(private_key, signed_data)

    return {
        "type": "DNS_RESPONSE",
        "status": "SUCCESS",
        "transaction_id": transaction_id,
        "nonce": nonce,
        "name": name,
        "record_type": record_type,
        "address": address,
        "ttl": TTL_SECONDS,
        "inception": inception,
        "expiration": expiration,
        "key_id": key_id,
        "public_key": public_key_to_base64(public_key),
        "signature": signature,
    }


# Attack simulation, used only when the server starts with --attack

def resign_response(response, private_key):
    """Recompute the signature over a response's current fields."""
    signed_data = canonical_record(
        **{field: response[field] for field in SIGNED_FIELDS}
    )
    response["signature"] = sign_record(private_key, signed_data)
    return response


def apply_attack(response, private_key, attack_state):
    """
    Modify a valid signed response the way an attacker would.
    Error responses and normal mode are passed through unchanged.
    """
    mode = attack_state["mode"]

    if mode is None or response.get("status") != "SUCCESS":
        return response

    response = dict(response)

    if mode == "tamper":
        logging.warning(
            "ATTACK tamper: changing address %s -> %s after signing",
            response["address"],
            FAKE_ADDRESS,
        )
        response["address"] = FAKE_ADDRESS

    elif mode == "badsig":
        raw = bytearray(base64.b64decode(response["signature"]))
        raw[0] ^= 0x01
        response["signature"] = base64.b64encode(bytes(raw)).decode("ascii")
        logging.warning("ATTACK badsig: flipped one bit of the signature")

    elif mode == "wrongkey":
        attacker_private, attacker_public = attack_state["attacker_keys"]
        response["address"] = FAKE_ADDRESS
        response["key_id"] = public_key_fingerprint(attacker_public)
        response["public_key"] = public_key_to_base64(attacker_public)
        resign_response(response, attacker_private)
        logging.warning(
            "ATTACK wrongkey: fake address %s signed with attacker key %s",
            FAKE_ADDRESS,
            response["key_id"][:16] + "...",
        )

    elif mode == "keyspoof":
        attacker_private, attacker_public = attack_state["attacker_keys"]
        response["address"] = FAKE_ADDRESS
        response["public_key"] = public_key_to_base64(attacker_public)
        resign_response(response, attacker_private)
        logging.warning(
            "ATTACK keyspoof: attacker key sent under the trusted key ID"
        )

    elif mode == "expired":
        now = datetime.now(timezone.utc)
        response["inception"] = (now - timedelta(hours=2)).isoformat()
        response["expiration"] = (now - timedelta(hours=1)).isoformat()
        resign_response(response, private_key)
        logging.warning(
            "ATTACK expired: validly signed, but expired at %s",
            response["expiration"],
        )

    elif mode == "replay":
        cache_key = (response["name"], response["record_type"])

        with attack_state["lock"]:
            captured = attack_state["replay_cache"].get(cache_key)

            if captured is None:
                attack_state["replay_cache"][cache_key] = dict(response)
                logging.warning(
                    "ATTACK replay: captured response for %s, "
                    "forwarding it normally this time",
                    response["name"],
                )
                return response

        # The attacker copies the new query's ID and nonce into the old response so it passes the ID check
        # The signature still covers the original ID and nonce, so verification fails.
        replayed = dict(captured)
        replayed["transaction_id"] = response["transaction_id"]
        replayed["nonce"] = response["nonce"]
        logging.warning(
            "ATTACK replay: resending captured response for %s "
            "with the new transaction ID and nonce",
            response["name"],
        )
        return replayed

    return response


# Networking

def handle_client(
    connection,
    client_address,
    records,
    private_key,
    public_key,
    attack_state,
):
    """Receive queries from one client and send responses."""
    logging.info("Client connected: %s", client_address)

    key_id = public_key_fingerprint(public_key)

    try:
        with connection:
            input_stream = connection.makefile("r", encoding="utf-8")
            output_stream = connection.makefile(
                "w",
                encoding="utf-8",
            )

            for line in input_stream:
                if not line.strip():
                    continue

                try:
                    query = json.loads(line)
                    logging.info(
                        "Received query: id=%s name=%s type=%s",
                        query.get("transaction_id"),
                        query.get("name"),
                        query.get("record_type"),
                    )

                    response = create_signed_response(
                        query,
                        records,
                        private_key,
                        public_key,
                        key_id,
                    )

                    response = apply_attack(
                        response,
                        private_key,
                        attack_state,
                    )

                except json.JSONDecodeError:
                    response = {
                        "type": "DNS_RESPONSE",
                        "status": "ERROR",
                        "error": "Invalid JSON request",
                    }

                if response.get("status") == "SUCCESS":
                    logging.info(
                        "Sending SUCCESS response: %s -> %s (signature %s...)",
                        response.get("name"),
                        response.get("address"),
                        response.get("signature", "")[:16],
                    )
                else:
                    logging.info(
                        "Sending ERROR response: %s",
                        response.get("error"),
                    )

                output_stream.write(json.dumps(response) + "\n")
                output_stream.flush()

    except Exception as error:
        logging.error("Client error: %s", error)

    finally:
        logging.info("Client disconnected: %s", client_address)


def start_server(attack=None):
    """Start the DNS security server."""
    records = load_records()
    private_key, public_key = generate_or_load_keys()
    key_id = public_key_fingerprint(public_key)

    attack_state = {
        "mode": attack,
        "attacker_keys": None,
        "replay_cache": {},
        "lock": threading.Lock(),
    }

    if attack in ("wrongkey", "keyspoof"):
        attack_state["attacker_keys"] = generate_key_pair()

    logging.info("Loaded %d DNS record names", len(records))
    logging.info("Trusted key identifier: %s", key_id)
    logging.info("Signed fields: %s", ", ".join(SIGNED_FIELDS))
    logging.info("Unsigned fields: %s", ", ".join(UNSIGNED_FIELDS))

    if attack:
        logging.warning(
            "ATTACK MODE '%s': %s",
            attack,
            ATTACK_MODES[attack],
        )

    logging.info("Listening on %s:%s", HOST, PORT)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        # Wake up once a second so Ctrl+C works on Windows.
        server_socket.settimeout(1.0)

        while True:
            try:
                connection, client_address = server_socket.accept()
            except socket.timeout:
                continue

            connection.settimeout(None)

            client_thread = threading.Thread(
                target=handle_client,
                args=(
                    connection,
                    client_address,
                    records,
                    private_key,
                    public_key,
                    attack_state,
                ),
                daemon=True,
            )
            client_thread.start()


def parse_arguments():
    """Read command-line options."""
    parser = argparse.ArgumentParser(description="DNS security server")
    parser.add_argument(
        "--attack",
        choices=sorted(ATTACK_MODES),
        help="Simulate an attacker modifying responses (for demos)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    arguments = parse_arguments()

    try:
        start_server(arguments.attack)
    except KeyboardInterrupt:
        logging.info("Server stopped")