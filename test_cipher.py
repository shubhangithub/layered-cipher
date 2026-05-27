"""End-to-end round-trip tests for the layered cipher.

Run directly (``python test_cipher.py``) or via pytest. The core property is
simple: for any valid input, ``decrypt(encrypt(x)) == x`` -- including after a
round trip through a file on disk.
"""

import os
import random
import tempfile

import cipher


def _random_pair(rng):
    number = "".join(rng.choice("0123456789") for _ in range(16))
    pin = "".join(rng.choice("0123456789") for _ in range(4))
    return number, pin


def test_round_trip_random():
    rng = random.Random(1234)
    for _ in range(2000):
        number, pin = _random_pair(rng)
        payload = cipher.encrypt(number, pin)
        assert cipher.decrypt(payload) == (number, pin)


def test_round_trip_edge_cases():
    cases = [
        ("0000000000000000", "0000"),
        ("9999999999999999", "9999"),
        ("0123456789012345", "6789"),
        ("1000000000000001", "0001"),
        ("4000123412341234", "1234"),
    ]
    for number, pin in cases:
        payload = cipher.encrypt(number, pin)
        assert cipher.decrypt(payload) == (number, pin)


def test_round_trip_through_disk():
    rng = random.Random(7)
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        for _ in range(200):
            number, pin = _random_pair(rng)
            cipher.save_encrypted(cipher.encrypt(number, pin), path)
            assert cipher.decrypt(cipher.load_encrypted(path)) == (number, pin)
    finally:
        os.remove(path)


def test_ciphertext_is_ascii_file():
    """The saved file must be pure ASCII (the 'ASCII values' claim)."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        cipher.save_encrypted(cipher.encrypt("1234567812345678", "4321"), path)
        with open(path, "rb") as fh:
            raw = fh.read()
        raw.decode("ascii")  # raises if any non-ASCII byte slipped through
    finally:
        os.remove(path)


def test_tamper_detection():
    """Modifying the ciphertext must be caught by the embedded checksum."""
    payload = cipher.encrypt("4539123412341234", "5678")
    # Flip one character of the ciphertext grid.
    ch = payload["ciphertext"][0][0]
    payload["ciphertext"][0][0] = chr(ord(ch) ^ 1)
    try:
        cipher.decrypt(payload)
    except cipher.IntegrityError:
        return
    raise AssertionError("tampering was not detected")


def test_seed_is_reproducible():
    a = cipher.encrypt("1111222233334444", "5555", seed=42)
    b = cipher.encrypt("1111222233334444", "5555", seed=42)
    assert a == b


def test_rejects_bad_input():
    for bad in [("123", "4321"), ("1234567812345678", "12"),
                ("12345678abcd5678", "4321"), (12345678, "4321")]:
        try:
            cipher.encrypt(*bad)
        except ValueError:
            continue
        except TypeError:
            continue
        raise AssertionError(f"expected rejection for {bad!r}")


def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} test(s) passed.")


if __name__ == "__main__":
    _run()
