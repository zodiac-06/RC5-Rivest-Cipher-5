"""
Tests for the RC5 implementation.

    python -m unittest -v

The tests use only the standard library. Random inputs come from a seeded
generator, so every run checks exactly the same cases.
"""

import random
import unittest
from decimal import Decimal, getcontext

from rc5 import MAGIC_CONSTANTS, RC5, pad, unpad
from vectors import TEST_VECTORS


def random_bytes(rng, length):
    return bytes(rng.randrange(256) for _ in range(length))


class PublishedVectors(unittest.TestCase):
    """The implementation must reproduce ciphertexts published by others."""

    def test_encrypt_matches_published_ciphertext(self):
        for source, w, r, key, plaintext, ciphertext in TEST_VECTORS:
            cipher = RC5(bytes.fromhex(key), w, r)
            with self.subTest(source=source, variant=cipher.name, plaintext=plaintext):
                got = cipher.encrypt_block(bytes.fromhex(plaintext))
                self.assertEqual(got.hex().upper(), ciphertext)

    def test_decrypt_recovers_published_plaintext(self):
        for source, w, r, key, plaintext, ciphertext in TEST_VECTORS:
            cipher = RC5(bytes.fromhex(key), w, r)
            with self.subTest(source=source, variant=cipher.name, plaintext=plaintext):
                got = cipher.decrypt_block(bytes.fromhex(ciphertext))
                self.assertEqual(got.hex().upper(), plaintext)

    def test_rivest_examples_follow_the_papers_chain(self):
        # In the paper each example's plaintext is the previous ciphertext and
        # each key byte j is (first ciphertext word) mod (255 - j). Rebuilding
        # the chain from scratch must land on the same five examples.
        paper = [v for v in TEST_VECTORS if v[0] == "Rivest 1994"]
        key, block = bytes(16), bytes(8)
        for _, _, _, expected_key, expected_plain, expected_cipher in paper:
            self.assertEqual(key.hex().upper(), expected_key)
            self.assertEqual(block.hex().upper(), expected_plain)
            cipher = RC5(key, 32, 12)
            block = cipher.encrypt_block(block)
            self.assertEqual(block.hex().upper(), expected_cipher)
            first_word = cipher.block_to_words(block)[0]
            key = bytes(first_word % (255 - j) for j in range(16))

    def test_rfc2040_cbc_vector_with_non_zero_iv(self):
        # RFC 2040 section 9.3: R = 0, key = 00, IV = 0102030405060708,
        # P = 1020304050607080  ->  C = 8B9DED91CE7794A6
        cipher = RC5(bytes.fromhex("00"), 32, 0)
        iv = bytes.fromhex("0102030405060708")
        sealed = cipher.encrypt_cbc(bytes.fromhex("1020304050607080"), iv)
        self.assertEqual(sealed[:8], iv)
        self.assertEqual(sealed[8:16].hex().upper(), "8B9DED91CE7794A6")


class MagicConstants(unittest.TestCase):
    def test_constants_come_from_e_and_the_golden_ratio(self):
        getcontext().prec = 60
        e = Decimal(1).exp()
        phi = (1 + Decimal(5).sqrt()) / 2

        def odd(x):                       # the odd integer nearest to x
            floor = int(x)
            return floor if floor % 2 == 1 else floor + 1

        for w, (P, Q) in MAGIC_CONSTANTS.items():
            with self.subTest(w=w):
                self.assertEqual(odd((e - 2) * 2 ** w), P)
                self.assertEqual(odd((phi - 1) * 2 ** w), Q)


class WordOperations(unittest.TestCase):
    def test_rotations(self):
        cipher = RC5(b"key", 32, 12)
        self.assertEqual(cipher.rotl(0x80000001, 1), 0x00000003)
        self.assertEqual(cipher.rotr(0x00000003, 1), 0x80000001)
        self.assertEqual(cipher.rotl(0x12345678, 0), 0x12345678)
        self.assertEqual(cipher.rotl(0x12345678, 32), 0x12345678)
        # Only the low 5 bits of the amount matter for 32-bit words.
        self.assertEqual(cipher.rotl(0x12345678, 37), cipher.rotl(0x12345678, 5))

    def test_rotr_undoes_rotl_for_every_word_size(self):
        rng = random.Random(1)
        for w in (16, 32, 64):
            cipher = RC5(b"key", w, 1)
            for _ in range(200):
                x = rng.getrandbits(w)
                n = rng.getrandbits(w)
                self.assertEqual(cipher.rotr(cipher.rotl(x, n), n), x)


class KeyExpansion(unittest.TestCase):
    def test_table_size_and_word_range(self):
        for w in (16, 32, 64):
            for r in (0, 1, 12, 255):
                cipher = RC5(b"some key", w, r)
                self.assertEqual(len(cipher.S), 2 * (r + 1))
                self.assertTrue(all(0 <= s < 2 ** w for s in cipher.S))

    def test_key_bytes_are_packed_little_endian(self):
        cipher = RC5(bytes(range(1, 7)), 32, 12)
        self.assertEqual(cipher.key_to_words(bytes(range(1, 7))),
                         [0x04030201, 0x00000605])

    def test_empty_key_is_allowed(self):
        cipher = RC5(b"", 32, 12)
        self.assertEqual(cipher.name, "RC5-32/12/0")
        block = b"ABCDEFGH"
        self.assertEqual(cipher.decrypt_block(cipher.encrypt_block(block)), block)

    def test_different_keys_give_different_tables(self):
        self.assertNotEqual(RC5(b"key-one", 32, 12).S, RC5(b"key-two", 32, 12).S)


class BlockRoundTrip(unittest.TestCase):
    def test_decrypt_undoes_encrypt_for_many_parameters(self):
        rng = random.Random(2)
        for w in (16, 32, 64):
            for r in (0, 1, 2, 12, 20, 255):
                for key_length in (0, 1, 5, 16, 24, 255):
                    cipher = RC5(random_bytes(rng, key_length), w, r)
                    with self.subTest(variant=cipher.name):
                        for _ in range(5):
                            block = random_bytes(rng, cipher.block_size)
                            sealed = cipher.encrypt_block(block)
                            self.assertEqual(len(sealed), cipher.block_size)
                            self.assertEqual(cipher.decrypt_block(sealed), block)

    def test_encryption_changes_the_block(self):
        cipher = RC5(b"mysecretkey12345", 32, 12)
        self.assertNotEqual(cipher.encrypt_block(b"ABCDEFGH"), b"ABCDEFGH")

    def test_trace_records_every_round(self):
        cipher = RC5(b"mysecretkey12345", 32, 12)
        trace = []
        sealed = cipher.encrypt_block(b"ABCDEFGH", trace)
        self.assertEqual([step for step, _, _ in trace], list(range(13)))
        self.assertEqual(cipher.words_to_block(*trace[-1][1:]), sealed)


class Avalanche(unittest.TestCase):
    def test_one_bit_change_flips_about_half_the_output(self):
        rng = random.Random(3)
        cipher = RC5(b"mysecretkey12345", 32, 12)
        total = 0
        trials = 300
        for _ in range(trials):
            block = bytearray(random_bytes(rng, 8))
            first = cipher.encrypt_block(bytes(block))
            block[rng.randrange(8)] ^= 1 << rng.randrange(8)
            second = cipher.encrypt_block(bytes(block))
            total += sum(bin(a ^ b).count("1") for a, b in zip(first, second))
        average = total / trials
        self.assertTrue(28 <= average <= 36, "average was %.1f of 64 bits" % average)


class Padding(unittest.TestCase):
    def test_pad_always_adds_between_one_and_block_size_bytes(self):
        for length in range(0, 40):
            padded = pad(b"x" * length, 8)
            self.assertEqual(len(padded) % 8, 0)
            self.assertTrue(1 <= len(padded) - length <= 8)
            self.assertEqual(unpad(padded, 8), b"x" * length)

    def test_full_block_gets_a_whole_extra_block(self):
        self.assertEqual(pad(b"12345678", 8), b"12345678" + b"\x08" * 8)

    def test_bad_padding_is_rejected(self):
        for bad in (b"", b"1234567", b"1234567\x00", b"1234567\x09",
                    b"123456\x01\x02", b"12345\x03\x03\x02"):
            with self.subTest(data=bad):
                with self.assertRaises(ValueError):
                    unpad(bad, 8)


class Modes(unittest.TestCase):
    def test_ecb_and_cbc_round_trip_for_every_length(self):
        rng = random.Random(4)
        for w in (16, 32, 64):
            cipher = RC5(b"mysecretkey12345", w, 12)
            for length in range(0, 3 * cipher.block_size + 2):
                message = random_bytes(rng, length)
                with self.subTest(w=w, length=length):
                    self.assertEqual(cipher.decrypt_ecb(cipher.encrypt_ecb(message)), message)
                    self.assertEqual(cipher.decrypt_cbc(cipher.encrypt_cbc(message)), message)

    def test_cbc_output_is_iv_plus_whole_blocks(self):
        cipher = RC5(b"mysecretkey12345", 32, 12)
        sealed = cipher.encrypt_cbc(b"hello")             # 5 bytes -> 1 block
        self.assertEqual(len(sealed), 8 + 8)
        sealed = cipher.encrypt_cbc(b"12345678")          # full block -> 2 blocks
        self.assertEqual(len(sealed), 8 + 16)

    def test_ecb_repeats_but_cbc_does_not(self):
        cipher = RC5(b"mysecretkey12345", 32, 12)
        message = b"SAMEDATA" * 3
        ecb = cipher.encrypt_ecb(message)
        self.assertEqual(ecb[0:8], ecb[8:16])
        self.assertEqual(ecb[8:16], ecb[16:24])
        cbc = cipher.encrypt_cbc(message)
        self.assertEqual(len({cbc[8:16], cbc[16:24], cbc[24:32]}), 3)

    def test_cbc_uses_a_fresh_iv_each_time(self):
        cipher = RC5(b"mysecretkey12345", 32, 12)
        self.assertNotEqual(cipher.encrypt_cbc(b"same message"),
                            cipher.encrypt_cbc(b"same message"))

    def test_cbc_is_deterministic_for_a_fixed_iv(self):
        cipher = RC5(b"mysecretkey12345", 32, 12)
        iv = bytes(8)
        self.assertEqual(cipher.encrypt_cbc(b"same message", iv),
                         cipher.encrypt_cbc(b"same message", iv))

    def test_wrong_key_does_not_reveal_the_message(self):
        message = b"RC5 mini project demo: hello, world!"
        sealed = RC5(b"mysecretkey12345", 32, 12).encrypt_cbc(message, bytes(8))
        wrong = RC5(b"lysecretkey12345", 32, 12)
        try:
            self.assertNotEqual(wrong.decrypt_cbc(sealed), message)
        except ValueError:
            pass                                          # rejected: also fine

    def test_unicode_text_survives(self):
        cipher = RC5(b"mysecretkey12345", 32, 12)
        text = "RC5 ✓ नमस्ते"
        sealed = cipher.encrypt_cbc(text.encode("utf-8"))
        self.assertEqual(cipher.decrypt_cbc(sealed).decode("utf-8"), text)


class InputValidation(unittest.TestCase):
    def test_bad_parameters_are_rejected(self):
        with self.assertRaises(ValueError):
            RC5(b"key", w=24)
        with self.assertRaises(ValueError):
            RC5(b"key", r=-1)
        with self.assertRaises(ValueError):
            RC5(b"key", r=256)
        with self.assertRaises(ValueError):
            RC5(b"k" * 256)
        with self.assertRaises(TypeError):
            RC5("a text key that was not encoded")

    def test_wrong_block_length_is_rejected(self):
        cipher = RC5(b"key", 32, 12)
        for bad in (b"", b"1234567", b"123456789"):
            with self.assertRaises(ValueError):
                cipher.encrypt_block(bad)
            with self.assertRaises(ValueError):
                cipher.decrypt_block(bad)

    def test_bad_ciphertext_and_iv_lengths_are_rejected(self):
        cipher = RC5(b"key", 32, 12)
        for bad in (b"", b"12345", b"12345678"):          # last one: IV only
            with self.assertRaises(ValueError):
                cipher.decrypt_cbc(bad)
        for bad in (b"", b"12345"):
            with self.assertRaises(ValueError):
                cipher.decrypt_ecb(bad)
        with self.assertRaises(ValueError):
            cipher.encrypt_cbc(b"message", iv=b"short")


if __name__ == "__main__":
    unittest.main()
