# DNS security server
# DNS security server

import json
import logging
import socket
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dnssec_crypto import (
    canonical_record,
    generate_or_load_keys,
    public_key_fingerprint,
    public_key_to_base64,
    sign_record,
)


HOST = "127.0.0.1"
PORT = 53535
RECORDS_FILE = Path("records.json")
TTL_SECONDS = 300


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


def handle_client(connection, client_address, records, private_key, public_key):
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
                        "Received query for %s",
                        query.get("name"),
                    )

                    response = create_signed_response(
                        query,
                        records,
                        private_key,
                        public_key,
                        key_id,
                    )

                except json.JSONDecodeError:
                    response = {
                        "type": "DNS_RESPONSE",
                        "status": "ERROR",
                        "error": "Invalid JSON request",
                    }

                logging.info(
                    "Sending %s response",
                    response.get("status"),
                )

                output_stream.write(json.dumps(response) + "\n")
                output_stream.flush()

    except Exception as error:
        logging.error("Client error: %s", error)

    finally:
        logging.info("Client disconnected: %s", client_address)


def start_server():
    """Start the DNS security server."""
    records = load_records()
    private_key, public_key = generate_or_load_keys()
    key_id = public_key_fingerprint(public_key)

    logging.info("Loaded %d DNS record names", len(records))
    logging.info("Trusted key identifier: %s", key_id)
    logging.info("Listening on %s:%s", HOST, PORT)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )
        server_socket.bind((HOST, PORT))
        server_socket.listen()

        while True:
            connection, client_address = server_socket.accept()

            client_thread = threading.Thread(
                target=handle_client,
                args=(
                    connection,
                    client_address,
                    records,
                    private_key,
                    public_key,
                ),
                daemon=True,
            )
            client_thread.start()


if __name__ == "__main__":
    start_server()