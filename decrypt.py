"""Command-line front end for decrypting a file produced by encrypt.py.

Examples
--------
    python decrypt.py                       # reads encrypted.json
    python decrypt.py -i secret.json
"""

import argparse

import cipher


def main():
    parser = argparse.ArgumentParser(description="Decrypt a file produced by encrypt.py.")
    parser.add_argument("-i", "--in", dest="infile", default="encrypted.json",
                        help="input file (default: encrypted.json)")
    args = parser.parse_args()

    try:
        payload = cipher.load_encrypted(args.infile)
    except FileNotFoundError:
        raise SystemExit(f"error: file not found: {args.infile}")

    number, pin = cipher.decrypt(payload)
    print(f"Number: {number}")
    print(f"PIN:    {pin}")


if __name__ == "__main__":
    main()
