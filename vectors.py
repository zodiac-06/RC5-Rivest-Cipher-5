"""
Published RC5 test vectors, used by both demo.py and test_rc5.py.

Each entry is (source, w, r, key, plaintext, ciphertext), all in hex.
Blocks are written as bytes in memory order. RC5 words are little-endian, so
the paper's word pair "EEDBA521 6D8F4B15" is the byte string 21A5DBEE154B8F6D.

Sources (full references are in README.md):
    Rivest 1994    "The RC5 Encryption Algorithm", RC5-32/12/16 examples
    RFC 2040       Baldwin & Rivest, 1996, section 9.3
    Krovetz draft  "RC6 and RC5 Test Vectors for Multiple Block Sizes"
"""

TEST_VECTORS = [
    # Rivest, "The RC5 Encryption Algorithm" (1994), section "RC5-32/12/16 examples".
    ("Rivest 1994", 32, 12, "00000000000000000000000000000000",
     "0000000000000000", "21A5DBEE154B8F6D"),
    ("Rivest 1994", 32, 12, "915F4619BE41B2516355A50110A9CE91",
     "21A5DBEE154B8F6D", "F7C013AC5B2B8952"),
    ("Rivest 1994", 32, 12, "783348E75AEB0F2FD7B169BB8DC16787",
     "F7C013AC5B2B8952", "2F42B3B70369FC92"),
    ("Rivest 1994", 32, 12, "DC49DB1375A5584F6485B413B5F12BAF",
     "2F42B3B70369FC92", "65C178B284D197CC"),
    ("Rivest 1994", 32, 12, "5269F149D41BA0152497574D7F153125",
     "65C178B284D197CC", "EB44E415DA319824"),
    # RFC 2040 (Baldwin & Rivest, 1996), section 9.3. With an all-zero IV and
    # one block, RC5-CBC is the same as encrypting that single block.
    ("RFC 2040", 32, 0, "00", "0000000000000000", "7A7BBA4D79111D1E"),
    ("RFC 2040", 32, 0, "00", "FFFFFFFFFFFFFFFF", "797BBA4D78111D1E"),
    ("RFC 2040", 32, 1, "11", "0000000000000000", "2F759FE7AD86A378"),
    # Krovetz, "RC6 and RC5 Test Vectors for Multiple Block Sizes" (IETF draft).
    ("Krovetz draft", 16, 16, "0001020304050607", "00010203", "23A8D72E"),
    ("Krovetz draft", 32, 20, "000102030405060708090A0B0C0D0E0F",
     "0001020304050607", "2A0EDC0E9431FF73"),
    ("Krovetz draft", 64, 24,
     "000102030405060708090A0B0C0D0E0F1011121314151617",
     "000102030405060708090A0B0C0D0E0F", "A46772820EDBCE0235ABEA32AE7178DA"),
]
