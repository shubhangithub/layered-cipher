"""A reversible, multi-layer cipher built on a 16x16 integer matrix.

The cipher takes a 16-digit number and a 4-digit PIN and runs them through
four stacked, individually reversible layers:

    Layer 0 - Scatter   : split the 20 digits into 7 packets and hide each
                          digit at a random column inside a 16x16 grid that is
                          otherwise filled with decoy noise. Packet sizes and
                          digit positions are stored inside the same grid so the
                          process can be reversed.
    Layer 1 - Wheel spin: replace each value with its step distance from the
                          previous value on a 16-position wheel (a delta /
                          modular encoding done per row).
    Layer 2 - Binary    : rewrite every value through its binary representation,
                          shifting digits by a key derived from the parity of
                          the bit counts.
    Layer 3 - Matrix    : transpose and row-swap the grid `rank` times, fold the
                          matrix trace into every element, subtract the rank,
                          then map each number to its ASCII / Unicode character.
                          The rank and trace are stashed in a key row so the
                          layer can be undone.

`decrypt` applies the exact inverse of every layer, in reverse order, and
recovers the original number and PIN.

The encrypted artifact is a dict (``ciphertext`` characters + a ``key`` row)
that round-trips losslessly through JSON via ``save_encrypted`` /
``load_encrypted``.
"""

from __future__ import annotations

import hashlib
import json

import numpy as np


class IntegrityError(Exception):
    """Raised when an encrypted payload fails its checksum (tamper/corruption)."""

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

N = 16            # the grid is N x N
DATA_ROWS = 7     # rows 0..6 carry the hidden digits (7 packets)
NUM_DIGITS = 20   # 16-digit number + 4-digit PIN

# Each combo lists how many size-2, size-3 and size-4 packets to use.
# Every combo describes 7 packets whose sizes sum to 20.
PACKET_COMBOS = [[1, 6, 0], [2, 4, 1], [3, 2, 2], [4, 0, 3]]
PACKET_SIZES = [2, 3, 4]


# ---------------------------------------------------------------------------
# Layer 0 - scatter the digits into a noisy grid
# ---------------------------------------------------------------------------

def _layer0_encrypt(digits, rng):
    """Hide ``digits`` (20 ints) in an NxN grid full of decoy noise."""
    combo = PACKET_COMBOS[int(rng.integers(0, len(PACKET_COMBOS)))]
    packet_sizes = []
    for size, count in zip(PACKET_SIZES, combo):
        packet_sizes.extend([size] * count)
    rng.shuffle(packet_sizes)  # 7 sizes summing to 20

    grid = rng.integers(0, 10, size=(N, N)).astype(np.int64)  # decoy noise 0-9
    index_locations = []  # column used for each digit, in order

    di = 0
    for row in range(DATA_ROWS):
        cols = rng.choice(N, size=packet_sizes[row], replace=False)
        for col in cols:
            grid[row][int(col)] = digits[di]
            index_locations.append(int(col))
            di += 1

    # Embed the metadata needed to reverse the scatter.
    for j in range(DATA_ROWS):
        grid[7][j] = packet_sizes[j]
    for j in range(N):
        grid[8][j] = index_locations[j]            # first 16 positions
    for j in range(NUM_DIGITS - N):
        grid[9][j] = index_locations[N + j]        # remaining 4 positions
    return grid


def _layer0_decrypt(grid):
    """Recover the 16-digit number and 4-digit PIN from the grid."""
    packet_sizes = [int(grid[7][j]) for j in range(DATA_ROWS)]
    index_locations = (
        [int(grid[8][j]) for j in range(N)]
        + [int(grid[9][j]) for j in range(NUM_DIGITS - N)]
    )

    digits = []
    di = 0
    for row in range(DATA_ROWS):
        for _ in range(packet_sizes[row]):
            digits.append(int(grid[row][index_locations[di]]))
            di += 1

    number = "".join(str(d) for d in digits[:16])
    pin = "".join(str(d) for d in digits[16:20])
    return number, pin


# ---------------------------------------------------------------------------
# Layer 1 - spin the wheel (per-row modular delta encoding)
# ---------------------------------------------------------------------------

def _layer1_encrypt(grid):
    out = grid.copy()
    for r in range(N):
        prev = 0
        for c in range(N):
            cur = int(grid[r][c])
            out[r][c] = (cur - prev) % N
            prev = cur
    return out


def _layer1_decrypt(grid):
    out = grid.copy()
    for r in range(N):
        acc = 0
        for c in range(N):
            acc = (acc + int(grid[r][c])) % N
            out[r][c] = acc
    return out


# ---------------------------------------------------------------------------
# Layer 2 - binary transformation
# ---------------------------------------------------------------------------

def _shift_digits_forward(bits):
    """Shift every digit of a binary string by a parity-derived key."""
    digits = [int(ch) for ch in bits]
    if len(bits) % 2 == 0:
        evens = sum(1 for d in digits if d % 2 == 0)
        delta = 3 if evens % 2 == 0 else 1
    else:
        odds = sum(1 for d in digits if d % 2 != 0)
        delta = 2 if odds % 2 == 0 else 4
    return "".join(str(d + delta) for d in digits)


def _shift_digits_inverse(text):
    """Inverse of :func:`_shift_digits_forward`.

    The shift always flips digit parity in a way that lets us recover the key
    from the number of odd digits in the shifted (decimal) string.
    """
    digits = [int(ch) for ch in text]
    odds = sum(1 for d in digits if d % 2 != 0)
    if len(text) % 2 == 0:
        delta = 3 if odds % 2 == 0 else 1
    else:
        delta = 2 if odds % 2 == 0 else 4
    return "".join(str(d - delta) for d in digits)


def _layer2_encrypt(grid):
    out = grid.copy()
    for r in range(N):
        for c in range(N):
            out[r][c] = int(_shift_digits_forward(format(int(grid[r][c]), "b")))
    return out


def _layer2_decrypt(grid):
    out = grid.copy()
    for r in range(N):
        for c in range(N):
            out[r][c] = int(_shift_digits_inverse(str(int(grid[r][c]))), 2)
    return out


# ---------------------------------------------------------------------------
# Layer 3 - matrix manipulation + ASCII conversion
# ---------------------------------------------------------------------------

def _swap_first_last_rows(grid):
    out = grid.copy()
    out[[0, N - 1]] = out[[N - 1, 0]]
    return out


def _layer3_encrypt(grid, rng):
    rank = int(np.linalg.matrix_rank(grid))

    work = grid.copy()
    for _ in range(rank):                 # swap rows then transpose, rank times
        work = _swap_first_last_rows(work)
        work = work.T.copy()

    trace = int(np.trace(work))
    work = work + trace                   # fold the trace into every element
    work = work - rank                    # subtract the rank from every element

    # ASCII layer: map each integer to its character.
    ciphertext = [[chr(int(work[r][c])) for c in range(N)] for r in range(N)]

    # Key row: stash rank and trace at random indices, with pointers in the
    # last two slots, so the layer can be reversed without guessing.
    key = [int(rng.integers(0, 256)) for _ in range(N)]
    r_idx = int(rng.integers(0, N - 2))
    t_idx = int(rng.integers(0, N - 2))
    while t_idx == r_idx:
        t_idx = int(rng.integers(0, N - 2))
    key[r_idx] = rank
    key[t_idx] = trace
    key[N - 2] = r_idx
    key[N - 1] = t_idx
    return ciphertext, key


def _layer3_decrypt(ciphertext, key):
    r_idx, t_idx = key[N - 2], key[N - 1]
    rank, trace = key[r_idx], key[t_idx]

    work = np.array(
        [[ord(ciphertext[r][c]) for c in range(N)] for r in range(N)],
        dtype=np.int64,
    )
    work = work + rank
    work = work - trace

    for _ in range(rank):                 # inverse of the forward swap/transpose
        work = work.T.copy()
        work = _swap_first_last_rows(work)
    return work


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _checksum(ciphertext, key):
    """SHA-256 over the ciphertext + key row: an anti-tampering fingerprint."""
    blob = json.dumps({"c": ciphertext, "k": key}, ensure_ascii=True, sort_keys=True)
    return hashlib.sha256(blob.encode("ascii")).hexdigest()


def _validate(number, pin):
    if not (isinstance(number, str) and number.isdigit() and len(number) == 16):
        raise ValueError("number must be a string of exactly 16 digits")
    if not (isinstance(pin, str) and pin.isdigit() and len(pin) == 4):
        raise ValueError("pin must be a string of exactly 4 digits")


def encrypt(number, pin, seed=None):
    """Encrypt a 16-digit number and 4-digit PIN.

    Returns a JSON-serialisable dict with the ciphertext characters and the
    key row. Pass ``seed`` for reproducible output (useful in demos/tests).
    """
    _validate(number, pin)
    rng = np.random.default_rng(seed)
    digits = [int(ch) for ch in (number + pin)]

    grid = _layer0_encrypt(digits, rng)
    grid = _layer1_encrypt(grid)
    grid = _layer2_encrypt(grid)
    ciphertext, key = _layer3_encrypt(grid, rng)

    return {
        "dim": N,
        "ciphertext": ciphertext,
        "key": key,
        "checksum": _checksum(ciphertext, key),
    }


def decrypt(payload, verify=True):
    """Reverse :func:`encrypt`. Returns ``(number, pin)``.

    If ``verify`` is true and the payload carries a checksum, the ciphertext is
    fingerprinted and compared before decrypting; a mismatch (tampering or
    corruption) raises :class:`IntegrityError`.
    """
    ciphertext, key = payload["ciphertext"], payload["key"]

    if verify and "checksum" in payload:
        if _checksum(ciphertext, key) != payload["checksum"]:
            raise IntegrityError("checksum mismatch: payload was tampered with or corrupted")

    grid = _layer3_decrypt(ciphertext, key)
    grid = _layer2_decrypt(grid)
    grid = _layer1_decrypt(grid)
    return _layer0_decrypt(grid)


def save_encrypted(payload, path):
    """Write the encrypted payload to ``path`` as ASCII-safe JSON."""
    with open(path, "w", encoding="ascii") as fh:
        json.dump(payload, fh, ensure_ascii=True)


def load_encrypted(path):
    """Load a payload written by :func:`save_encrypted`."""
    with open(path, "r", encoding="ascii") as fh:
        return json.load(fh)
