"""Command-line front end for encrypting a 16-digit number + 4-digit PIN.

Examples
--------
    python encrypt.py                       # prompts for input
    python encrypt.py -n 1234567812345678 -p 4321
    python encrypt.py -n 1234567812345678 -p 4321 -o secret.json --show
"""

import argparse

import cipher


def main():
    parser = argparse.ArgumentParser(description="Encrypt a 16-digit number and 4-digit PIN.")
    parser.add_argument("-n", "--number", help="16-digit number (originally a debit-card number)")
    parser.add_argument("-p", "--pin", help="4-digit PIN")
    parser.add_argument("-o", "--out", default="encrypted.json", help="output file (default: encrypted.json)")
    parser.add_argument("--seed", type=int, default=None, help="optional seed for reproducible output")
    parser.add_argument("--show", action="store_true", help="also print the ciphertext grid")
    args = parser.parse_args()

    number = args.number or input("Enter 16-digit number: ").strip()
    pin = args.pin or input("Enter 4-digit PIN: ").strip()

    try:
        payload = cipher.encrypt(number, pin, seed=args.seed)
    except ValueError as exc:
        raise SystemExit(f"error: {exc}")

    cipher.save_encrypted(payload, args.out)
    print(f"Encrypted -> {args.out}")

    if args.show:
        print("\nCiphertext grid (ASCII characters):")
        for row in payload["ciphertext"]:
            print(" ".join(repr(ch)[1:-1] for ch in row))


if __name__ == "__main__":
    main()
