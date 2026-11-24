# DNS Security Simulation

A small Python client-server DNS application that demonstrates the core security idea behind DNSSEC. The server signs each DNS answer with its private RSA key. The client checks the signature against a trusted public-key fingerprint (the trust anchor) and only accepts the IP address if every check passes.

CSC 154, Computer System Attacks and Countermeasures, Fall 2026.

## Project structure

| File | Purpose |
| --- | --- |
| `server.py` | Authoritative DNS server. Loads records, signs responses, logs queries. |
| `client.py` | DNS client. Sends queries and validates every response before trusting it. |
| `dnssec_crypto.py` | Shared crypto module: keys, fingerprints, canonical format, signing, verifying. |
| `test_crypto.py` | Local tests of the crypto module, run without any networking. |
| `records.json` | The DNS records the server is authoritative for. |
| `requirements.txt` | Python dependencies. |

Generated at runtime and never committed: `keys/` (the server's key pair) and `trust_anchor.txt` (the trusted fingerprint).

## Requirements

- Python 3.10 or newer
- The `cryptography` library (installed from `requirements.txt`)

## Setup

From the project folder:

```
python -m venv venv
```

Activate the virtual environment.

- Windows: `venv\Scripts\activate`
- Mac or Linux: `source venv/bin/activate`

Install the dependencies:

```
pip install -r requirements.txt
```

## Running the tests

```
python test_crypto.py
```

This runs 14 tests, including the five the project requires: a valid signature, a modified record, a modified IP address, an incorrect key, and a corrupted signature. All should report `ok`.

## Running the project

Use two terminals, both in the project folder with the virtual environment active. Run both programs from the project folder so they find `records.json`, `keys/`, and `trust_anchor.txt`.

**Terminal 1, start the server:**

```
python server.py
```

On the first run the server creates `keys/private_key.pem` and `keys/public_key.pem`, and writes the key fingerprint to `trust_anchor.txt`. Later runs reuse the same keys. The server listens on `127.0.0.1:53535` over TCP.

**Terminal 2, run the client:**

```
python client.py
```

Enter a domain name (for example `www.example.com`) and a record type (press Enter for `A`).

Example of an accepted response:

```
Sending query for www.example.com...
ACCEPTED: The DNS response passed all validation checks.
Address: 192.168.1.10
TTL: 300 seconds
```

Example of a rejected response:

```
REJECTED: Unknown domain name: nope.example.com
```

## Message protocol

Messages are JSON objects, one per line, over a TCP connection.

**Query (client to server)**

```json
{
  "type": "DNS_QUERY",
  "transaction_id": "3f1c...",
  "name": "www.example.com",
  "record_type": "A",
  "nonce": "Xk2..."
}
```

**Successful response (server to client)**

```json
{
  "type": "DNS_RESPONSE",
  "status": "SUCCESS",
  "transaction_id": "3f1c...",
  "nonce": "Xk2...",
  "name": "www.example.com",
  "record_type": "A",
  "address": "192.168.1.10",
  "ttl": 300,
  "inception": "2026-11-24T20:00:00+00:00",
  "expiration": "2026-11-24T20:05:00+00:00",
  "key_id": "ace1483e...",
  "public_key": "<base64 DER public key>",
  "signature": "<base64 RSA-PSS signature>"
}
```

**Error response.** For an unknown name, an unsupported record type, or a malformed query, the server returns `"status": "ERROR"` with an `"error"` message. Error responses carry no address and no signature, and the client never accepts an address from them.

## Cryptographic design

- **Key pair:** RSA, 2048 bits, stored in PEM format in `keys/`. The private key never leaves the server.
- **Signature scheme:** RSA-PSS with SHA-256 as the message digest.
- **Key identifier:** the SHA-256 hash of the public key in DER form, written as lowercase hex.
- **Trust anchor:** `trust_anchor.txt` holds the key identifier the client trusts. The client rejects any response whose public key does not hash to this value, even if the signature is valid for that key.

### Canonical record format

Before signing, the server builds this string and encodes it as UTF-8:

```
name|record_type|address|ttl|key_id|inception|expiration|transaction_id|nonce
```

Example:

```
www.example.com|A|192.168.1.10|300|ace1483e...|2026-11-24T20:00:00+00:00|2026-11-24T20:05:00+00:00|3f1c...|Xk2...
```

Rules that keep it deterministic:

- The name is lowercased and any trailing dot is removed.
- The record type is uppercased.
- The TTL is written as a whole number.
- Any `\` in a field is written as `\\`, and any `|` as `\|`, so a field can never fake an extra separator.

The client rebuilds the same string from the response fields and verifies the signature over it. Changing any signed field causes verification to fail.

### Signed and unsigned fields

| Field | Signed? | Notes |
| --- | --- | --- |
| `name`, `record_type`, `address`, `ttl` | Yes | The DNS answer itself |
| `key_id` | Yes | Binds the signature to one key |
| `inception`, `expiration` | Yes | Validity period, used to reject stale data |
| `transaction_id`, `nonce` | Yes | Ties the response to one query, which blocks replay |
| `public_key` | Indirectly | Must hash to the signed `key_id` and to the trust anchor |
| `type`, `status`, `signature` | No | Used only for processing |

### Client validation order

The client accepts the address only if every check passes, in this order:

1. The message type is `DNS_RESPONSE` and the status is `SUCCESS`.
2. The transaction ID and nonce match the query.
3. The name and record type match the query.
4. All required fields are present.
5. The `key_id` matches the trust anchor.
6. The public key decodes, and its fingerprint matches the trust anchor.
7. The current time is between `inception` and `expiration`.
8. The signature verifies over the rebuilt canonical record.

If any check fails, the client prints `REJECTED` with the reason and does not display the address.

## Limitations

- **No chain of trust.** Real DNSSEC links keys from the root zone down through each parent zone. This project trusts one key directly through a local fingerprint file.
- **Responses are signed per query.** Real DNSSEC signs record sets in advance. This project signs each response, including the transaction ID and nonce, so that a replayed response fails verification.
- **No confidentiality.** Like DNSSEC, the project provides integrity and authentication only. Queries and answers travel in plain text.
- **Unprotected private key.** The private key is stored without a password. It is excluded from Git and the submission, but anyone with access to the `keys/` folder could use it.
- **Unsigned errors.** Error responses are not signed, so an attacker could forge a "does not exist" answer. The client never accepts an address from one, but it can be denied the answer. Real DNSSEC handles this with signed denial records (NSEC/NSEC3).
- **Local only.** The server and client run on `127.0.0.1` over TCP and only support `A` records.
