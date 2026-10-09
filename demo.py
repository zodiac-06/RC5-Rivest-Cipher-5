"""
Live demonstration of the RC5 block cipher.

    python demo.py                 guided demo, pauses between sections
    python demo.py --auto          run everything with default inputs, no pauses
    python demo.py --section 2 5   run only the listed sections (1-8)
    python demo.py --rounds 16 --word-size 64

Sections:
    1  Parameters and key expansion
    2  One block, round by round (encrypt, then decrypt)
    3  Published test vectors
    4  Encrypting a whole message (CBC mode)
    5  Avalanche effect
    6  ECB vs CBC: why the mode matters
    7  Decrypting with the wrong key
    8  Brute force on a tiny key, and what it means for real key sizes
"""

import argparse
import os
import sys
import time

from rc5 import MAGIC_CONSTANTS, RC5, pad, split_blocks
from vectors import TEST_VECTORS

DEFAULT_MESSAGE = "RC5 mini project demo: hello, world!"
DEFAULT_KEY = "mysecretkey12345"      # 16 characters = 128-bit key

# ----------------------------------------------------------------------
# Printing helpers (plain ASCII so it looks the same in any terminal)
# ----------------------------------------------------------------------
def heading(number, title):
    print()
    print("=" * 72)
    print(" %d. %s" % (number, title))
    print("=" * 72)


def hex_bytes(data):
    return data.hex(" ").upper()


def hex_word(cipher, value):
    return "%0*X" % (cipher.w // 4, value)


def printable(data):
    """Show bytes as text, replacing anything unprintable with a dot."""
    return "".join(chr(c) if 32 <= c < 127 else "." for c in data)


def as_text(data):
    """Show decrypted bytes as text when they are valid, readable UTF-8."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return printable(data)
    return text if text.isprintable() else printable(data)


def count_different_bits(x, y):
    return sum(bin(p ^ q).count("1") for p, q in zip(x, y))


def flip_bit(data, position):
    """Return a copy of data with one bit inverted."""
    changed = bytearray(data)
    changed[position // 8] ^= 1 << (position % 8)
    return bytes(changed)


def human_time(seconds):
    year = 365.25 * 24 * 3600
    if seconds < 1:
        return "%.0f milliseconds" % (seconds * 1000)
    if seconds < 120:
        return "%.1f seconds" % seconds
    if seconds < 2 * 3600:
        return "%.1f minutes" % (seconds / 60)
    if seconds < 2 * 86400:
        return "%.1f hours" % (seconds / 3600)
    if seconds < 2 * year:
        return "%.1f days" % (seconds / 86400)
    years = seconds / year
    if years < 1e6:
        return "{:,.0f} years".format(years)
    if years < 1e9:
        return "%.0f million years" % (years / 1e6)
    if years < 1e12:
        return "%.0f billion years" % (years / 1e9)
    return "about 10^%d years" % (len(str(int(years))) - 1)


# ----------------------------------------------------------------------
# 1. Parameters and key expansion
# ----------------------------------------------------------------------
def section_key_expansion(cipher, key):
    heading(1, "Parameters and key expansion")
    P, Q = MAGIC_CONSTANTS[cipher.w]
    print("Variant      : %s   (RC5-w/r/b)" % cipher.name)
    print("  w = %-3d bits per word  -> block = 2 words = %d bits (%d bytes)"
          % (cipher.w, 2 * cipher.w, cipher.block_size))
    print("  r = %-3d rounds" % cipher.r)
    print("  b = %-3d key bytes      -> %d-bit key" % (cipher.b, 8 * cipher.b))
    print("  t = 2(r+1) = %d sub-keys in the table S" % cipher.t)
    print()
    print("Secret key   : %s" % hex_bytes(key))

    L = cipher.key_to_words(key)
    print()
    print("Step 1  key bytes packed into %d word(s) L (little-endian):" % len(L))
    print("        L = " + " ".join(hex_word(cipher, x) for x in L))

    S0 = cipher.initial_table()
    shown = 4 if cipher.w <= 32 else 2      # how many sub-keys fit on a line
    print()
    print("Step 2  S filled from the magic constants (same for every key):")
    print("        P = %s  (from e)" % hex_word(cipher, P))
    print("        Q = %s  (from the golden ratio)" % hex_word(cipher, Q))
    print("        S[0..%d] = %s ..."
          % (shown - 1, " ".join(hex_word(cipher, x) for x in S0[:shown])))

    print()
    print("Step 3  key mixed into S (3 passes, %d steps):"
          % (3 * max(cipher.t, len(L))))
    print("        S[0..%d] = %s ..."
          % (shown - 1, " ".join(hex_word(cipher, x) for x in cipher.S[:shown])))
    print("        S[%d]   = %s  (last sub-key)"
          % (cipher.t - 1, hex_word(cipher, cipher.S[-1])))
    print()
    print("The key itself is never used again: encryption only uses S.")


# ----------------------------------------------------------------------
# 2. One block, round by round
# ----------------------------------------------------------------------
def section_one_block(cipher, message):
    heading(2, "One block, round by round")
    block = pad(message, cipher.block_size)[:cipher.block_size]
    A, B = cipher.block_to_words(block)
    print("Plaintext block : %s   '%s'" % (hex_bytes(block), printable(block)))
    print("Split into two words (little-endian):")
    print("    A = %s   B = %s" % (hex_word(cipher, A), hex_word(cipher, B)))
    print()
    print("ENCRYPT   A = ((A xor B) <<< B) + S[2i]")
    print("          B = ((B xor A) <<< A) + S[2i+1]")
    print()

    trace = []
    ciphertext = cipher.encrypt_block(block, trace)
    width = cipher.w // 4
    print("  %-22s %-*s  %-*s" % ("step", width, "A", width, "B"))
    for round_number, a, b in trace:
        label = "add S[0], S[1]" if round_number == 0 else "round %d" % round_number
        print("  %-22s %s  %s" % (label, hex_word(cipher, a), hex_word(cipher, b)))
    print()
    print("Ciphertext block: %s" % hex_bytes(ciphertext))

    print()
    print("DECRYPT   the same steps undone in reverse (subtract, rotate right)")
    print()
    trace = []
    recovered = cipher.decrypt_block(ciphertext, trace)
    labels = ["ciphertext"] + ["undo round %d" % i for i in range(cipher.r, 0, -1)]
    rows = list(zip(labels, trace))
    if len(rows) > 5:                 # keep the screen short: first and last steps
        rows = rows[:3] + [("...", None)] + rows[-2:]
    for label, entry in rows:
        if entry is None:
            print("  " + label)
        else:
            print("  %-22s %s  %s" % (label, hex_word(cipher, entry[1]),
                                      hex_word(cipher, entry[2])))
    A, B = cipher.block_to_words(recovered)
    print("  %-22s %s  %s" % ("subtract S[0], S[1]", hex_word(cipher, A),
                              hex_word(cipher, B)))
    print()
    print("Recovered block : %s   '%s'" % (hex_bytes(recovered), printable(recovered)))
    print("Matches the original plaintext: %s" % ("YES" if recovered == block else "NO"))


# ----------------------------------------------------------------------
# 3. Published test vectors
# ----------------------------------------------------------------------
def section_test_vectors():
    heading(3, "Published test vectors")
    print("A known key and plaintext must give exactly the published ciphertext.")
    print()
    print("  result variant        source         ciphertext produced")
    passed = 0
    for source, w, r, key, plaintext, expected in TEST_VECTORS:
        cipher = RC5(bytes.fromhex(key), w, r)
        got = cipher.encrypt_block(bytes.fromhex(plaintext))
        back = cipher.decrypt_block(got)
        ok = got == bytes.fromhex(expected) and back == bytes.fromhex(plaintext)
        passed += ok
        print("  [%s] %-14s %-14s %s"
              % ("PASS" if ok else "FAIL", cipher.name, source, got.hex().upper()))
    print()
    if passed == len(TEST_VECTORS):
        print("All %d vectors match, and each one decrypts back to its plaintext."
              % passed)
    else:
        print("%d of %d vectors FAILED." % (len(TEST_VECTORS) - passed,
                                           len(TEST_VECTORS)))
    return passed == len(TEST_VECTORS)


# ----------------------------------------------------------------------
# 4. Encrypting a whole message
# ----------------------------------------------------------------------
def section_message(cipher, message):
    heading(4, "Encrypting a whole message (CBC mode)")
    padded = pad(message, cipher.block_size)
    print("Message    : '%s'  (%d bytes)" % (as_text(message), len(message)))
    print("Padded     : %d bytes = %d blocks of %d bytes (PKCS#7 padding adds %d)"
          % (len(padded), len(padded) // cipher.block_size, cipher.block_size,
             len(padded) - len(message)))

    sealed = cipher.encrypt_cbc(message)
    iv, ciphertext = sealed[:cipher.block_size], sealed[cipher.block_size:]
    print("Random IV  : %s" % hex_bytes(iv))
    print("Ciphertext :")
    for block in split_blocks(ciphertext, cipher.block_size):
        print("    " + hex_bytes(block))

    recovered = cipher.decrypt_cbc(sealed)
    print("Decrypted  : '%s'" % as_text(recovered))
    print("Matches the original message: %s" % ("YES" if recovered == message else "NO"))

    again = cipher.encrypt_cbc(message)
    print()
    print("Encrypting the SAME message again gives a different ciphertext,")
    print("because a new random IV is used each time:")
    print("    " + hex_bytes(again[cipher.block_size:2 * cipher.block_size]) + " ...")
    return sealed


# ----------------------------------------------------------------------
# 5. Avalanche effect
# ----------------------------------------------------------------------
def average_changed_bits(key, w, r, trials, flip_key=False):
    """Average number of ciphertext bits that change when ONE random bit of
    the plaintext (or of the key) is flipped."""
    total = 0
    block_size = 2 * (w // 8)
    for _ in range(trials):
        block = os.urandom(block_size)
        if flip_key:
            position = int.from_bytes(os.urandom(2), "big") % (8 * len(key))
            first = RC5(key, w, r).encrypt_block(block)
            second = RC5(flip_bit(key, position), w, r).encrypt_block(block)
        else:
            position = int.from_bytes(os.urandom(2), "big") % (8 * block_size)
            cipher = RC5(key, w, r)
            first = cipher.encrypt_block(block)
            second = cipher.encrypt_block(flip_bit(block, position))
        total += count_different_bits(first, second)
    return total / trials


def section_avalanche(cipher, key, message):
    heading(5, "Avalanche effect")
    bits = 8 * cipher.block_size
    block = pad(message, cipher.block_size)[:cipher.block_size]
    changed = flip_bit(block, 0)
    c1 = cipher.encrypt_block(block)
    c2 = cipher.encrypt_block(changed)
    print("Flip ONE bit of the plaintext and compare the two ciphertexts:")
    print("  plaintext  1 : %s" % hex_bytes(block))
    print("  plaintext  2 : %s" % hex_bytes(changed))
    print("  ciphertext 1 : %s" % hex_bytes(c1))
    print("  ciphertext 2 : %s" % hex_bytes(c2))
    print("  ciphertext bits that differ: %d of %d"
          % (count_different_bits(c1, c2), bits))

    trials = 300
    print()
    print("Average over %d random blocks, one random plaintext bit flipped:" % trials)
    print("  rounds   bits changed (ideal = %d, i.e. 50%%)" % (bits // 2))
    for r in sorted(set([1, 2, 3, 4, 6, 8, 12, cipher.r])):
        if r == 0:
            continue
        average = average_changed_bits(key, cipher.w, r, trials)
        bar = "#" * int(round(40 * average / bits))
        print("  %4d     %5.1f  (%4.1f%%)  %s" % (r, average, 100 * average / bits, bar))
    print()
    if key:
        average = average_changed_bits(key, cipher.w, cipher.r, trials, flip_key=True)
        print("One random KEY bit flipped, %d rounds: %.1f of %d bits change (%.1f%%)."
              % (cipher.r, average, bits, 100 * average / bits))
    print("With few rounds a small change stays small; that is why reduced-round")
    print("RC5 can be attacked and the full number of rounds matters.")


# ----------------------------------------------------------------------
# 6. ECB vs CBC
# ----------------------------------------------------------------------
def section_modes(cipher):
    heading(6, "ECB vs CBC: why the mode matters")
    one_block = (b"SAMEDATA" * 2)[:cipher.block_size]
    message = one_block * 3
    print("Message = the block '%s' repeated 3 times." % printable(one_block))
    print()
    print("ECB (each block encrypted on its own):")
    ecb = cipher.encrypt_ecb(message)
    for block in split_blocks(ecb, cipher.block_size)[:3]:
        print("    " + hex_bytes(block))
    print("  -> identical ciphertext blocks: the repetition is visible.")
    print()
    print("CBC (each block XORed with the previous ciphertext block first):")
    cbc = cipher.encrypt_cbc(message)
    for block in split_blocks(cbc, cipher.block_size)[1:4]:
        print("    " + hex_bytes(block))
    print("  -> all different: the pattern is hidden.")


# ----------------------------------------------------------------------
# 7. Wrong key
# ----------------------------------------------------------------------
def section_wrong_key(cipher, key, message):
    heading(7, "Decrypting with the wrong key")
    sealed = cipher.encrypt_cbc(message)
    wrong_key = flip_bit(key, 0) if key else b"\x01"
    print("Right key : %s" % hex_bytes(key))
    print("Wrong key : %s" % hex_bytes(wrong_key))
    print("            (only ONE bit is different)")
    wrong = RC5(wrong_key, cipher.w, cipher.r)

    first_block = sealed[cipher.block_size:2 * cipher.block_size]
    garbage = wrong.decrypt_block(first_block)
    print()
    print("First ciphertext block decrypted with the wrong key:")
    print("    %s   '%s'" % (hex_bytes(garbage), printable(garbage)))
    try:
        result = wrong.decrypt_cbc(sealed)
        print("Whole message with the wrong key: '%s'  (garbage)" % printable(result))
    except ValueError as error:
        print("Whole message with the wrong key: rejected")
        print("    reason: %s" % error)
    print("With the right key: '%s'" % as_text(cipher.decrypt_cbc(sealed)))


# ----------------------------------------------------------------------
# 8. Brute force
# ----------------------------------------------------------------------
def section_brute_force(cipher):
    heading(8, "Brute force on a tiny key")
    known_plaintext = (b"KNOWNTXT" * 2)[:cipher.block_size]
    secret_key = os.urandom(2)
    target = RC5(secret_key, cipher.w, cipher.r).encrypt_block(known_plaintext)
    print("A secret 2-byte (16-bit) key was chosen at random.")
    print("The attacker knows one plaintext block and its ciphertext:")
    print("    plaintext  : %s" % hex_bytes(known_plaintext))
    print("    ciphertext : %s" % hex_bytes(target))
    print("Trying the 65,536 possible keys one by one (a few seconds) ...")

    start = time.perf_counter()
    found = None
    tried = 0
    for candidate in range(65536):
        guess = candidate.to_bytes(2, "big")
        tried += 1
        if RC5(guess, cipher.w, cipher.r).encrypt_block(known_plaintext) == target:
            found = guess
            break
        if tried % 4096 == 0:             # one dot per 4,096 keys tried
            print(".", end="", flush=True)
    elapsed = time.perf_counter() - start
    rate = tried / elapsed

    print()
    if found is None:
        print("Key not found (this should never happen).")
        return
    print("Key found : %s after %s keys in %.2f seconds (%s keys/second)"
          % (hex_bytes(found), "{:,}".format(tried), elapsed,
             "{:,.0f}".format(rate)))
    print("Correct   : %s" % ("YES" if found == secret_key else
                              "NO - a different key that also maps this block"))
    print()
    print("Average time to find a key at this speed (half the key space):")
    for key_bits in (16, 40, 56, 64, 72, 128):
        seconds = (2 ** (key_bits - 1)) / rate
        print("  %3d-bit key : %s" % (key_bits, human_time(seconds)))
    print()
    print("Real attacks are far faster than this Python loop: distributed.net")
    print("found a 56-bit RC5 key in 1997 and a 64-bit key in 2002, and a 72-bit")
    print("search has been running since 2002. A 128-bit key is out of reach.")


# ----------------------------------------------------------------------
# Main program
# ----------------------------------------------------------------------
def ask(prompt, default, auto):
    """Ask for a line of input; Enter (or --auto) keeps the default."""
    if auto:
        return default
    try:
        answer = input("%s [%s]: " % (prompt, default)).strip()
    except EOFError:
        return default
    return answer or default


def pause(auto):
    if auto:
        return
    try:
        input("\nPress Enter to continue ...")
    except EOFError:
        pass


def main():
    parser = argparse.ArgumentParser(description="Live demonstration of RC5.")
    parser.add_argument("--word-size", type=int, default=32, choices=[16, 32, 64],
                        help="word size w in bits (default 32 -> 64-bit block)")
    parser.add_argument("--rounds", type=int, default=12,
                        help="number of rounds r, 0-255 (default 12)")
    parser.add_argument("--message", help="message to encrypt (skips the prompt)")
    parser.add_argument("--key", help="secret key as text (skips the prompt)")
    parser.add_argument("--section", type=int, nargs="+", choices=range(1, 9),
                        metavar="N", help="run only these sections (1-8)")
    parser.add_argument("--auto", action="store_true",
                        help="no prompts and no pauses; use the default inputs")
    args = parser.parse_args()
    if not 0 <= args.rounds <= 255:
        parser.error("--rounds must be between 0 and 255")

    # Never let an unusual character crash the demo on an old Windows console.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    print("RC5 block cipher - live demonstration")
    print("(Ronald L. Rivest, 1994 - educational implementation)")
    print()
    message_text = args.message or ask("Message to encrypt", DEFAULT_MESSAGE, args.auto)
    key_text = args.key or ask("Secret key (text)", DEFAULT_KEY, args.auto)
    message = message_text.encode("utf-8")
    key = key_text.encode("utf-8")
    if len(key) > 255:
        parser.error("the key must be at most 255 bytes long")

    cipher = RC5(key, args.word_size, args.rounds)
    sections = args.section or list(range(1, 9))

    for position, number in enumerate(sections):
        if number == 1:
            section_key_expansion(cipher, key)
        elif number == 2:
            section_one_block(cipher, message)
        elif number == 3:
            section_test_vectors()
        elif number == 4:
            section_message(cipher, message)
        elif number == 5:
            section_avalanche(cipher, key, message)
        elif number == 6:
            section_modes(cipher)
        elif number == 7:
            section_wrong_key(cipher, key, message)
        elif number == 8:
            section_brute_force(cipher)
        if position < len(sections) - 1:
            pause(args.auto)

    print()
    print("End of demonstration.")


if __name__ == "__main__":
    main()
