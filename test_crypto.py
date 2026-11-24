# Local tests for dnssec_crypto.py

# Run with:  python test_crypto.py

import base64
import tempfile
import unittest
from pathlib import Path

from dnssec_crypto import (
    canonical_record,
    generate_key_pair,
    generate_or_load_keys,
    public_key_fingerprint,
    public_key_from_base64,
    public_key_to_base64,
    sign_record,
    verify_signature,
)


def sample_fields(key_id, **changes):
    """Return a valid set of record fields, with optional changes."""
    fields = {
        "name": "www.example.com",
        "record_type": "A",
        "address": "192.168.1.10",
        "ttl": 300,
        "key_id": key_id,
        "inception": "2026-11-24T20:00:00+00:00",
        "expiration": "2026-11-24T20:05:00+00:00",
        "transaction_id": "abc123",
        "nonce": "random-value",
    }
    fields.update(changes)
    return fields


class TestDnssecCrypto(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # One trusted key pair (the real server) and one attacker key pair.
        cls.private_key, cls.public_key = generate_key_pair()
        cls.attacker_private, cls.attacker_public = generate_key_pair()
        cls.key_id = public_key_fingerprint(cls.public_key)

        cls.signed_data = canonical_record(**sample_fields(cls.key_id))
        cls.signature = sign_record(cls.private_key, cls.signed_data)

    # The five tests required by the project brief

    def test_1_valid_signature(self):
        """A correctly signed record verifies."""
        self.assertTrue(
            verify_signature(self.public_key, self.signed_data, self.signature)
        )

    def test_2_modified_record_name(self):
        """Changing the domain name breaks the signature."""
        tampered = canonical_record(
            **sample_fields(self.key_id, name="evil.example.com")
        )
        self.assertFalse(
            verify_signature(self.public_key, tampered, self.signature)
        )

    def test_3_modified_ip_address(self):
        """Changing the IP address breaks the signature."""
        tampered = canonical_record(
            **sample_fields(self.key_id, address="10.0.0.66")
        )
        self.assertFalse(
            verify_signature(self.public_key, tampered, self.signature)
        )

    def test_4_incorrect_key(self):
        """A signature does not verify under a different public key."""
        self.assertFalse(
            verify_signature(self.attacker_public, self.signed_data, self.signature)
        )

    def test_5_corrupted_signature(self):
        """Flipping one byte of the signature makes it invalid."""
        raw = bytearray(base64.b64decode(self.signature))
        raw[0] ^= 0x01
        corrupted = base64.b64encode(bytes(raw)).decode("ascii")
        self.assertFalse(
            verify_signature(self.public_key, self.signed_data, corrupted)
        )

    # Extra checks on the other signed fields

    def test_6_modified_ttl_and_times(self):
        """Changing the TTL or validity period breaks the signature."""
        for change in (
            {"ttl": 86400},
            {"expiration": "2030-01-01T00:00:00+00:00"},
            {"inception": "2020-01-01T00:00:00+00:00"},
        ):
            with self.subTest(change=change):
                tampered = canonical_record(**sample_fields(self.key_id, **change))
                self.assertFalse(
                    verify_signature(self.public_key, tampered, self.signature)
                )

    def test_7_modified_transaction_id_and_nonce(self):
        """A response signed for one query fails for another (replay)."""
        for change in ({"transaction_id": "zzz999"}, {"nonce": "other-nonce"}):
            with self.subTest(change=change):
                tampered = canonical_record(**sample_fields(self.key_id, **change))
                self.assertFalse(
                    verify_signature(self.public_key, tampered, self.signature)
                )

    def test_8_attacker_signs_with_own_key(self):
        """An attacker can produce a valid signature, but the fingerprint
        of the attacker's key does not match the trust anchor."""
        attacker_id = public_key_fingerprint(self.attacker_public)
        data = canonical_record(**sample_fields(attacker_id, address="10.0.0.66"))
        signature = sign_record(self.attacker_private, data)

        self.assertTrue(verify_signature(self.attacker_public, data, signature))
        self.assertNotEqual(attacker_id, self.key_id)

    def test_9_garbage_signature_does_not_crash(self):
        """Invalid base64 or an empty signature returns False, not an error."""
        for bad in ("not-base64!!", "", "AAAA"):
            with self.subTest(signature=bad):
                self.assertFalse(
                    verify_signature(self.public_key, self.signed_data, bad)
                )

    # Canonical format and key handling

    def test_10_canonical_format_is_deterministic(self):
        """Name case, trailing dots, and type case do not change the bytes."""
        a = canonical_record(**sample_fields(self.key_id))
        b = canonical_record(
            **sample_fields(self.key_id, name="WWW.Example.COM.", record_type="a")
        )
        self.assertEqual(a, b)
        self.assertTrue(a.startswith(b"www.example.com|A|192.168.1.10|300|"))

    def test_11_separator_cannot_shift_fields(self):
        """A "|" inside a field cannot be used to fake a different record."""
        a = canonical_record(**sample_fields(self.key_id, address="1.1.1.1|300"))
        b = canonical_record(**sample_fields(self.key_id, address="1.1.1.1"))
        self.assertNotEqual(a, b)

    def test_12_public_key_base64_round_trip(self):
        """A public key survives encoding into JSON and back."""
        encoded = public_key_to_base64(self.public_key)
        decoded = public_key_from_base64(encoded)
        self.assertEqual(public_key_fingerprint(decoded), self.key_id)

    def test_13_bad_public_key_is_rejected(self):
        """Garbage key data raises ValueError instead of loading."""
        with self.assertRaises(ValueError):
            public_key_from_base64("bm90IGEga2V5")  # "not a key"

    def test_14_keys_save_and_reload(self):
        """Keys are created once, then the same keys load on later runs,
        and the trust-anchor file holds the matching fingerprint."""
        with tempfile.TemporaryDirectory() as temp:
            key_dir = Path(temp) / "keys"
            anchor = Path(temp) / "trust_anchor.txt"

            _, first_public = generate_or_load_keys(key_dir, anchor)
            _, second_public = generate_or_load_keys(key_dir, anchor)

            first_id = public_key_fingerprint(first_public)
            self.assertEqual(first_id, public_key_fingerprint(second_public))
            self.assertEqual(anchor.read_text().strip(), first_id)
            self.assertTrue((key_dir / "private_key.pem").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)