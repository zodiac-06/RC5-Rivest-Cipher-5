# Demo plan and viva notes

These are speaking notes. Read them, run each section a few times, and then
say it in your own words. Every number below can be seen on screen by running
the section named next to it.

## Before the demo

```powershell
python --version           # 3.8 or newer
python -m unittest         # should end with: Ran 28 tests ... OK
python demo.py --auto      # full run-through, a few seconds
```

Open `rc5.py` in the editor next to the terminal so you can point at the code.

## 5-7 minute plan

Run `python demo.py`, type a message and a key when asked (or press Enter for
the defaults), and press Enter to move from section to section.

| Time | Section | What to say |
|---|---|---|
| 0:00 | Intro | RC5 is a symmetric block cipher by Ron Rivest, 1994. It is written RC5-w/r/b: word size, rounds, key bytes. I am using RC5-32/12/16: 64-bit block, 12 rounds, 128-bit key. It uses only addition, XOR and rotation. |
| 0:40 | 1. Key expansion | The key is not used directly. It is packed into words `L`, the table `S` is filled from two constants `P` and `Q`, and then the key is mixed into `S` in three passes. 12 rounds need 26 sub-keys. Point at `expand_key` in `rc5.py`. |
| 1:40 | 2. One block | The 8-byte block is split into `A` and `B`. First `S[0]` and `S[1]` are added. Each round: XOR the two halves, rotate by the other half, add a sub-key. The table shows `A` and `B` changing completely every round. Decryption undoes the same steps in reverse order and gives back the plaintext. Point at `encrypt_block` and `decrypt_block`. |
| 3:00 | 3. Test vectors | To prove the code is correct I compare it with ciphertexts published by Rivest, RFC 2040 and an IETF draft. All 11 match. |
| 3:30 | 4. Message | A real message is longer than one block, so it is padded and encrypted in CBC mode with a random IV. Decryption gives the message back. Encrypting again gives a different ciphertext because the IV is new. |
| 4:15 | 5. Avalanche | Flipping one plaintext bit changes about half of the ciphertext bits. With 1 round only about 15% change, so the number of rounds matters. |
| 5:00 | 6. ECB vs CBC | In ECB the three equal blocks give three equal ciphertexts. CBC hides that. The mode is as important as the cipher. |
| 5:30 | 7. Wrong key | With one key bit changed, decryption gives garbage and is rejected. |
| 6:00 | 8. Brute force | A 16-bit key is found in seconds. Each extra key bit doubles the work, so 128 bits is out of reach. distributed.net broke 56-bit RC5 in 1997 and 64-bit in 2002. |
| 6:40 | Close | Best known attack on 12 rounds needs 2^44 chosen plaintexts, so 16 to 20 rounds are recommended. RC5 was used in WTLS and IPsec and led to RC6. Today AES is used instead. |

If time is short, run `python demo.py --section 1 2 3 5 8`.

If the examiner wants a different variant: `python demo.py --rounds 16` or
`python demo.py --word-size 64 --rounds 16`.

## How to read the code

| In the paper | In `rc5.py` |
|---|---|
| `w`, `r`, `b` | `self.w`, `self.r`, `self.b` |
| `u = w/8` bytes per word | `self.word_bytes` |
| `t = 2(r+1)` | `self.t` |
| `P_w`, `Q_w` | `MAGIC_CONSTANTS[w]` |
| Key bytes to `L` | `key_to_words` |
| Initialise `S` | `initial_table` |
| Mix key into `S` | `mix` |
| Encryption | `encrypt_block` |
| Decryption | `decrypt_block` |
| `x <<< y`, `x >>> y` | `rotl(x, y)`, `rotr(x, y)` |

Two details worth knowing:

- Python integers have no fixed size, so every addition or subtraction is
  followed by `& self.mask` (mask = 2^w - 1). That is what "modulo 2^w" means
  in code.
- In `rotl(x, n)` the amount is reduced with `n %= w`. For w = 32 this keeps
  only the low 5 bits of the other word as the rotation amount.

## Viva questions

**1. What type of cipher is RC5?**
A symmetric-key block cipher. The same key encrypts and decrypts, and it works
on fixed-size blocks of 2w bits (32, 64 or 128).

**2. What does RC5-32/12/16 mean?**
32-bit words (so a 64-bit block), 12 rounds, 16-byte (128-bit) key.

**3. Which operations does it use, and why these?**
Addition modulo 2^w, XOR and data-dependent rotation. They are fast on any
processor and need no lookup tables. Mixing arithmetic addition with bitwise
XOR makes the cipher non-linear.

**4. What is a data-dependent rotation?**
The number of positions to rotate is not fixed; it is the value of the other
half of the block (its low log2(w) bits). So the rotation is different for
every plaintext and key, which makes it hard to track how differences spread.

**5. Why is there a key expansion step?**
Each round needs its own sub-keys. Expansion turns a key of any length into
2(r+1) words, makes every sub-key depend on every key byte, and is hard to
reverse.

**6. Where do P and Q come from?**
From e and the golden ratio: P = Odd((e - 2) * 2^w), Q = Odd((phi - 1) * 2^w).
They are public constants that anyone can recompute, so they cannot hide a
back door. `test_rc5.py` recomputes them.

**7. Why three passes in the mixing loop?**
The loop runs 3 * max(t, c) times so that both arrays are fully covered three
times and each entry is influenced by all the others.

**8. Why are S[0] and S[1] added before the first round?**
Without it the first rotation amount would be the raw plaintext, which the
attacker knows. Adding key material first hides the inputs to round 1.

**9. How does decryption work without a separate algorithm?**
Each operation has an inverse: subtraction undoes addition, right rotation
undoes left rotation, XOR undoes itself. Decryption applies the inverses in
reverse order with the same table S.

**10. Is RC5 a Feistel cipher?**
It is Feistel-like. Each half is updated using the other half, but unlike
classic Feistel both halves change in every round, so one RC5 round is like
two Feistel half-rounds.

**11. Why is padding needed, and which padding is used?**
The block cipher only accepts full blocks. PKCS#7 adds n bytes each of value
n. If the message is already a full block, a whole extra block is added so
the padding can always be removed without doubt.

**12. Difference between ECB and CBC?**
ECB encrypts each block independently, so equal blocks give equal ciphertext.
CBC XORs each block with the previous ciphertext block and starts from a
random IV, so patterns are hidden and the same message encrypts differently
each time.

**13. Does the IV have to be secret?**
No. It must be unpredictable and different for every message. It is sent
along with the ciphertext.

**14. What is the avalanche effect?**
A one-bit change in the plaintext or key should change about half of the
output bits. Section 5 of the demo measures about 50% from 4 rounds upwards.

**15. Is RC5 secure?**
It depends on the parameters. 12-round RC5-32 has a differential attack with
2^44 chosen plaintexts (Biryukov and Kushilevitz, 1998), so 12 rounds is too
few today; 16 to 20 rounds are recommended. With enough rounds and a 128-bit
key there is no practical attack on the cipher, but the 64-bit block limits
how much data can be safely encrypted under one key (about 2^32 blocks).

**16. How long would brute force take?**
A b-byte key has 2^(8b) possibilities. distributed.net found a 56-bit key in
250 days (1997) and a 64-bit key in 1,757 days (2002). A 128-bit key has
2^64 times more keys than a 64-bit key.

**17. What is a timing attack on RC5?**
If the processor takes longer to rotate by a larger amount, the total time of
an encryption leaks the rotation amounts, which depend on the sub-keys
(Handschuh and Heys, 1998). This Python code is not constant-time.

**18. Where was RC5 used?**
RFC 2040 for Internet protocols, IPsec ESP (RFC 2451), WTLS in WAP phones,
and the RSA Secret-Key Challenge. It was patented until 2015.

**19. How is RC6 related?**
RC6 was an AES finalist based on RC5. It uses four words instead of two and
adds a multiplication so that the rotation amount depends on all bits of a
word.

**20. RC5 compared with AES?**
AES has a fixed 128-bit block and fixed round counts, is an official
standard, and has hardware support in modern processors. RC5 is simpler and
more flexible but has a 64-bit block in its usual form and is not a current
standard.

**21. How do you know your implementation is correct?**
It reproduces 11 published test vectors from three independent sources, and
28 automated tests check that decryption reverses encryption for every word
size, many round counts and key lengths.

**22. What would you change for real-world use?**
Use an established library instead; if RC5 were required, use 64-bit words
and at least 16 rounds, derive the key with a proper key-derivation function,
add message authentication, and use constant-time code.

**23. Which external code or libraries did you use?**
No third-party libraries. Only Python standard-library modules. The algorithm
follows Rivest's published pseudo-code, the test vectors come from published
documents, and AI assistance (Claude) is acknowledged in the README.
