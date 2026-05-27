# layered-cipher

A reversible, **multi-layer cipher** in Python. It takes a 16-digit number and
a 4-digit PIN, runs them through four stacked transformation layers on a 16×16
integer matrix, and writes the result to an ASCII file. A matching decryption
routine reverses every layer and recovers the original input exactly.

> This started as a college project. The code here is a cleaned-up, fixed, and
> tested version: the original scripts had a broken file format and used numpy
> idioms that no longer exist in modern numpy, so the encrypt → file → decrypt
> pipeline didn't actually run end to end. It does now, and the round trip is
> covered by tests.

## What it does

```
plaintext  ──►  Layer 0  ──►  Layer 1  ──►  Layer 2  ──►  Layer 3  ──►  ciphertext file
(number+PIN)    scatter       wheel spin    binary        matrix +        (ASCII JSON)
                                            transform     ASCII
```

| Layer | Name | What happens | How it reverses |
|------:|------|--------------|-----------------|
| 0 | **Scatter** | The 20 digits are split into 7 packets and each digit is hidden at a random column of a 16×16 grid otherwise full of decoy noise. Packet sizes and digit positions are embedded back into the grid. | Read the embedded positions and pull the digits back out in order. |
| 1 | **Wheel spin** | Each value is replaced by its step distance from the previous value on a 16-position wheel (a per-row modular delta). | Walk the wheel forward, accumulating the steps. |
| 2 | **Binary** | Every value is rewritten through its binary form, shifting each bit-digit by a key derived from the parity of its bit counts. | Recover the key from the parity of the shifted digits and undo the shift. |
| 3 | **Matrix + ASCII** | The grid is transposed and row-swapped `rank` times, the matrix **trace** is folded into every element, the **rank** is subtracted, and each number is mapped to its ASCII/Unicode character. Rank and trace are stashed in a key row. | Map characters back to numbers, restore rank/trace from the key row, and invert the matrix operations. |

A **SHA-256 checksum** of the ciphertext is embedded in the output. On
decryption it is recomputed and compared, so any tampering or corruption of the
encrypted file is detected before decryption is attempted.

## Quick start

```bash
pip install -r requirements.txt

# Encrypt (writes encrypted.json). Omit -n/-p to be prompted.
python encrypt.py -n 4539123412341234 -p 5678 --show

# Decrypt
python decrypt.py -i encrypted.json
#   Number: 4539123412341234
#   PIN:    5678
```

Or use it as a library:

```python
import cipher

payload = cipher.encrypt("4539123412341234", "5678")
cipher.save_encrypted(payload, "encrypted.json")

number, pin = cipher.decrypt(cipher.load_encrypted("encrypted.json"))
```

## Tests

```bash
python test_cipher.py        # or: pytest
```

The suite verifies the core property — `decrypt(encrypt(x)) == x` — across
**2000 random inputs**, edge cases (all-zeros, all-nines, leading zeros), a full
round trip through a file on disk, that the saved file is **pure ASCII**, that
output is **reproducible** under a fixed seed, that **bad input is rejected**,
and that **tampering is detected** by the checksum.

## What this is (and isn't)

This is a portfolio / learning project that demonstrates reversible data
transformations, modular arithmetic, binary manipulation, and basic linear
algebra (rank, trace, transpose) — not a production cryptosystem. There is no
secret key in the cryptographic sense, so it should not be used to protect real
secrets. The embedded checksum provides integrity/tamper-detection, not
confidentiality against a determined attacker.

## Project layout

```
cipher.py        core: the four layers + encrypt/decrypt/save/load + checksum
encrypt.py       CLI: plaintext -> encrypted.json
decrypt.py       CLI: encrypted.json -> plaintext
test_cipher.py   end-to-end round-trip + integrity tests
```

## Résumé / LinkedIn bullet points (verified against this code)

- Built a reversible **multi-layer cipher in Python** that encodes input into a
  16×16 matrix and transforms it through modular "wheel-spin" arithmetic, binary
  digit manipulation, linear-algebra operations (matrix rank, trace, transpose,
  row swaps), and ASCII character conversion.
- Implemented a **decryption pipeline** that inverts every layer in reverse
  order to losslessly recover the original input — verified by a test suite that
  round-trips 2000+ random inputs and edge cases.
- Embedded **rank and trace metadata** in a dedicated key row so the matrix layer
  is fully reversible without it, and added a **SHA-256 integrity checksum** that
  detects tampering or corruption of the encrypted file.
- Hardened the project for modern tooling (numpy 2.x) and a robust ASCII-safe
  serialization format, taking the pipeline from non-running prototype to a
  tested, end-to-end working tool.
