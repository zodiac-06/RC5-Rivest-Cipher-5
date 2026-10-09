"""
RC5 block cipher - pure Python implementation (standard library only).

RC5 was designed by Ronald L. Rivest in 1994. A particular version is written
RC5-w/r/b, where

    w = word size in bits (16, 32 or 64). A block is two words = 2w bits.
    r = number of rounds (0..255)
    b = length of the secret key in bytes (0..255)

Rivest's "nominal" choice is RC5-32/12/16: 64-bit block, 12 rounds, 128-bit key.

The whole cipher uses only three operations on w-bit words:

    +     addition modulo 2^w
    ^     bitwise XOR
    <<<   left rotation, where the rotation amount comes from the DATA itself

This file follows the pseudo-code in Rivest's paper "The RC5 Encryption
Algorithm" (1994). It is written to be read and explained, not to be fast, and
it is NOT meant to protect real data.
"""

import os

# "Magic constants" used to fill the sub-key table before the key is mixed in.
#   P = Odd((e - 2)   * 2^w)     e   = 2.718281828... (base of natural logs)
#   Q = Odd((phi - 1) * 2^w)     phi = 1.618033988... (golden ratio)
# Odd(x) means "the odd integer nearest to x". Because they come from famous
# mathematical constants, nobody can claim the designer chose them to hide a
# back door ("nothing up my sleeve" numbers). test_rc5.py re-derives them.
MAGIC_CONSTANTS = {
    16: (0xB7E1, 0x9E37),
    32: (0xB7E15163, 0x9E3779B9),
    64: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15),
}


class RC5:
    """One RC5 cipher object = one key + one choice of (w, r)."""

    def __init__(self, key, w=32, r=12):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes, e.g. b'secret' or 'secret'.encode()")
        if w not in MAGIC_CONSTANTS:
            raise ValueError("word size w must be 16, 32 or 64")
        if not 0 <= r <= 255:
            raise ValueError("number of rounds r must be between 0 and 255")
        if len(key) > 255:
            raise ValueError("key must be at most 255 bytes long")

        self.w = w                        # word size in bits
        self.r = r                        # number of rounds
        self.b = len(key)                 # key length in bytes
        self.mask = (1 << w) - 1          # keeps results inside w bits (mod 2^w)
        self.word_bytes = w // 8          # u in the paper: bytes per word
        self.block_size = 2 * self.word_bytes   # block length in bytes
        self.t = 2 * (r + 1)              # number of sub-keys in the table S

        self.S = self.expand_key(bytes(key))

    @property
    def name(self):
        """The standard name of this variant, e.g. 'RC5-32/12/16'."""
        return "RC5-%d/%d/%d" % (self.w, self.r, self.b)

    # ------------------------------------------------------------------
    # Word operations
    # ------------------------------------------------------------------
    def rotl(self, x, n):
        """Rotate the w-bit word x left by n bits. Only the low log2(w) bits
        of n matter, so n is reduced modulo w first."""
        n %= self.w
        return ((x << n) | (x >> (self.w - n))) & self.mask

    def rotr(self, x, n):
        """Rotate the w-bit word x right by n bits (undoes rotl)."""
        n %= self.w
        return ((x >> n) | (x << (self.w - n))) & self.mask

    # ------------------------------------------------------------------
    # Key expansion: secret key (b bytes)  -->  sub-key table S (t words)
    # ------------------------------------------------------------------
    def key_to_words(self, key):
        """Step 1: copy the key bytes into an array L of c words
        (little-endian: the first key byte is the lowest byte of L[0])."""
        u = self.word_bytes
        c = max(1, -(-len(key) // u))     # ceil(b / u), and at least 1 word
        L = [0] * c
        for i in range(len(key) - 1, -1, -1):
            L[i // u] = ((L[i // u] << 8) + key[i]) & self.mask
        return L

    def initial_table(self):
        """Step 2: fill S with a fixed pattern that does not depend on the
        key: S[0] = P, then keep adding Q."""
        P, Q = MAGIC_CONSTANTS[self.w]
        S = [P]
        for _ in range(1, self.t):
            S.append((S[-1] + Q) & self.mask)
        return S

    def mix(self, S, L):
        """Step 3: mix the secret key into S. We make three passes over the
        larger of the two arrays, updating one entry of S and one entry of L
        each step. Every key byte ends up influencing every sub-key."""
        t, c = len(S), len(L)
        i = j = A = B = 0
        for _ in range(3 * max(t, c)):
            A = S[i] = self.rotl((S[i] + A + B) & self.mask, 3)
            B = L[j] = self.rotl((L[j] + A + B) & self.mask, A + B)
            i = (i + 1) % t
            j = (j + 1) % c
        return S

    def expand_key(self, key):
        """Run the three key-expansion steps and return the sub-key table."""
        return self.mix(self.initial_table(), self.key_to_words(key))

    # ------------------------------------------------------------------
    # Block <-> words helpers
    # ------------------------------------------------------------------
    def block_to_words(self, block):
        if len(block) != self.block_size:
            raise ValueError("block must be exactly %d bytes" % self.block_size)
        u = self.word_bytes
        A = int.from_bytes(block[:u], "little")
        B = int.from_bytes(block[u:], "little")
        return A, B

    def words_to_block(self, A, B):
        u = self.word_bytes
        return A.to_bytes(u, "little") + B.to_bytes(u, "little")

    # ------------------------------------------------------------------
    # Encryption and decryption of ONE block
    # ------------------------------------------------------------------
    def encrypt_block(self, block, trace=None):
        """Encrypt one block of 2w bits.

        If `trace` is a list, (round number, A, B) is appended after each
        step so the demo can show how the block changes round by round."""
        S, mask = self.S, self.mask
        A, B = self.block_to_words(block)

        # Add the first two sub-keys before any round ("key whitening").
        A = (A + S[0]) & mask
        B = (B + S[1]) & mask
        if trace is not None:
            trace.append((0, A, B))

        for i in range(1, self.r + 1):
            # Each round updates A using B, then B using the new A.
            # The amount of rotation is the other half of the data itself.
            A = (self.rotl(A ^ B, B) + S[2 * i]) & mask
            B = (self.rotl(B ^ A, A) + S[2 * i + 1]) & mask
            if trace is not None:
                trace.append((i, A, B))

        return self.words_to_block(A, B)

    def decrypt_block(self, block, trace=None):
        """Decrypt one block: the encryption steps undone in reverse order
        (subtract instead of add, rotate right instead of left)."""
        S, mask = self.S, self.mask
        A, B = self.block_to_words(block)
        if trace is not None:
            trace.append((self.r, A, B))

        for i in range(self.r, 0, -1):
            B = self.rotr((B - S[2 * i + 1]) & mask, A) ^ A
            A = self.rotr((A - S[2 * i]) & mask, B) ^ B
            if trace is not None:
                trace.append((i - 1, A, B))

        B = (B - S[1]) & mask
        A = (A - S[0]) & mask
        return self.words_to_block(A, B)

    # ------------------------------------------------------------------
    # Modes of operation: how to encrypt a message longer than one block
    # ------------------------------------------------------------------
    def encrypt_ecb(self, plaintext):
        """ECB: every block is encrypted on its own. Simple but leaks
        patterns - equal plaintext blocks give equal ciphertext blocks."""
        data = pad(plaintext, self.block_size)
        out = b""
        for block in split_blocks(data, self.block_size):
            out += self.encrypt_block(block)
        return out

    def decrypt_ecb(self, ciphertext):
        self.check_length(ciphertext)
        out = b""
        for block in split_blocks(ciphertext, self.block_size):
            out += self.decrypt_block(block)
        return unpad(out, self.block_size)

    def encrypt_cbc(self, plaintext, iv=None):
        """CBC: each plaintext block is XORed with the previous ciphertext
        block before encryption, so equal blocks no longer look equal.
        A fresh random IV starts the chain; it is not secret and is returned
        in front of the ciphertext (IV || ciphertext)."""
        if iv is None:
            iv = os.urandom(self.block_size)
        if len(iv) != self.block_size:
            raise ValueError("IV must be exactly %d bytes" % self.block_size)
        data = pad(plaintext, self.block_size)
        out = iv
        previous = iv
        for block in split_blocks(data, self.block_size):
            previous = self.encrypt_block(xor_bytes(block, previous))
            out += previous
        return out

    def decrypt_cbc(self, data):
        """Reverse of encrypt_cbc. Expects IV || ciphertext."""
        self.check_length(data)
        if len(data) < 2 * self.block_size:
            raise ValueError("ciphertext is too short (needs IV + one block)")
        blocks = split_blocks(data, self.block_size)
        out = b""
        for previous, block in zip(blocks, blocks[1:]):
            out += xor_bytes(self.decrypt_block(block), previous)
        return unpad(out, self.block_size)

    def check_length(self, data):
        if len(data) == 0 or len(data) % self.block_size != 0:
            raise ValueError(
                "ciphertext length must be a non-zero multiple of %d bytes"
                % self.block_size
            )


# ----------------------------------------------------------------------
# Small helpers shared by the modes
# ----------------------------------------------------------------------
def pad(data, block_size):
    """PKCS#7 padding: add n bytes, each with the value n, so the length
    becomes a multiple of the block size. A full block is added when the
    message already fits, so the padding can always be removed."""
    n = block_size - (len(data) % block_size)
    return bytes(data) + bytes([n]) * n


def unpad(data, block_size):
    """Remove PKCS#7 padding, checking that it is well formed."""
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("invalid padded data length")
    n = data[-1]
    if n < 1 or n > block_size or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid padding (wrong key or corrupted ciphertext)")
    return data[:-n]


def split_blocks(data, block_size):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def xor_bytes(x, y):
    return bytes(p ^ q for p, q in zip(x, y))
