# RC5 (Rivest Cipher 5)

A from-scratch Python implementation of the RC5 block cipher: key expansion,
block encryption and decryption, ECB and CBC modes, a guided live demo, and a
test suite checked against published test vectors. Cryptography mini project.

It uses the Python standard library only. It is written to be read and
explained, and it is **not** meant to protect real data.

## Files

| File | What it contains |
|---|---|
| `rc5.py` | The cipher: `RC5` class (key expansion, `encrypt_block`, `decrypt_block`, ECB, CBC) and PKCS#7 padding |
| `demo.py` | The live demonstration, in 8 short sections |
| `vectors.py` | Published test vectors used by the demo and the tests |
| `test_rc5.py` | 28 automated tests |
| `docs/DEMO_AND_VIVA.md` | A 5-7 minute demo plan and viva questions with answers |

## How to run

Needs Python 3.8 or newer. Nothing to install.

```powershell
git clone https://github.com/zodiac-06/RC5-Rivest-Cipher-5.git
cd RC5-Rivest-Cipher-5

python demo.py                 # guided demo: asks for a message and a key
python demo.py --auto          # same demo with default inputs, no pauses
python demo.py --section 2 5   # only some sections
python demo.py --rounds 16 --word-size 64

python -m unittest -v          # run all tests
```

Using the cipher from your own code:

```python
from rc5 import RC5

cipher = RC5(b"mysecretkey12345", w=32, r=12)     # RC5-32/12/16
sealed = cipher.encrypt_cbc(b"hello, world")      # random IV + ciphertext
print(cipher.decrypt_cbc(sealed))                 # b'hello, world'
```

## What RC5 is

RC5 is a symmetric block cipher designed by Ronald L. Rivest in 1994. The same
secret key encrypts and decrypts. Its special feature is that everything is a
parameter, so one algorithm gives a whole family written **RC5-w/r/b**:

| Parameter | Meaning | Allowed | Nominal |
|---|---|---|---|
| `w` | word size in bits; a block is two words (2w bits) | 16, 32, 64 | 32 (64-bit block) |
| `r` | number of rounds | 0 to 255 | 12 |
| `b` | key length in bytes | 0 to 255 | 16 (128-bit key) |

It uses only three operations on w-bit words, all fast on ordinary processors:

- `+` addition modulo 2^w
- `xor` bitwise exclusive-or
- `<<<` left rotation, where **the amount of rotation is taken from the data**

The data-dependent rotation is the idea RC5 is known for. Because the rotation
amount changes with every plaintext and key, the cipher needs no S-box tables.

## How it works

### 1. Key expansion

The secret key is stretched into a table `S` of `t = 2(r + 1)` words (26 words
for 12 rounds). Encryption uses only `S`, never the key directly.

1. **Key to words.** The `b` key bytes are copied into `c = ceil(b / (w/8))`
   words `L`, little-endian.
2. **Fill S with a fixed pattern.** `S[0] = P`, then `S[i] = S[i-1] + Q`.
   `P` and `Q` are "magic constants" taken from *e* and the golden ratio
   (`P = Odd((e - 2) * 2^w)`, `Q = Odd((phi - 1) * 2^w)`; for w = 32 they are
   `B7E15163` and `9E3779B9`). They are "nothing up my sleeve" numbers: anyone
   can recompute them, so they cannot hide a back door.
3. **Mix the key in.** Three passes over the larger of the two arrays:

   ```
   A = S[i] = (S[i] + A + B) <<< 3
   B = L[j] = (L[j] + A + B) <<< (A + B)
   i = (i + 1) mod t,   j = (j + 1) mod c
   ```

   After this every key byte affects every entry of `S`, and it is hard to go
   back from `S` to the key.

### 2. Encryption

The plaintext block is split into two words `A` and `B`.

```
A = A + S[0]
B = B + S[1]
for i = 1 to r:
    A = ((A xor B) <<< B) + S[2i]
    B = ((B xor A) <<< A) + S[2i + 1]
```

Each round updates both halves, and each half is rotated by an amount that
depends on the other half. The ciphertext is the final `A`, `B`.

### 3. Decryption

Every step is reversible, so decryption runs the rounds backwards: subtract
instead of add, rotate right instead of left.

```
for i = r down to 1:
    B = ((B - S[2i + 1]) >>> A) xor A
    A = ((A - S[2i])     >>> B) xor B
B = B - S[1]
A = A - S[0]
```

### 4. Messages longer than one block

RC5 itself encrypts exactly one block. `rc5.py` adds two modes on top:

- **ECB**: each block is encrypted separately. Equal plaintext blocks give
  equal ciphertext blocks, so patterns show through. Included only to
  demonstrate the weakness.
- **CBC**: each plaintext block is XORed with the previous ciphertext block
  before encryption, starting from a random IV. The IV is stored in front of
  the ciphertext.

Messages are padded with PKCS#7 so their length is a multiple of the block
size. CBC with this padding is what RFC 2040 calls RC5-CBC-Pad.

## Test cases

`python -m unittest -v` runs 28 tests. `python demo.py --section 3` shows the
published vectors live. All of these are reproduced exactly:

| Variant | Key | Plaintext | Ciphertext | Source |
|---|---|---|---|---|
| RC5-32/12/16 | `00000000000000000000000000000000` | `0000000000000000` | `21A5DBEE154B8F6D` | Rivest 1994 |
| RC5-32/12/16 | `915F4619BE41B2516355A50110A9CE91` | `21A5DBEE154B8F6D` | `F7C013AC5B2B8952` | Rivest 1994 |
| RC5-32/12/16 | `783348E75AEB0F2FD7B169BB8DC16787` | `F7C013AC5B2B8952` | `2F42B3B70369FC92` | Rivest 1994 |
| RC5-32/12/16 | `DC49DB1375A5584F6485B413B5F12BAF` | `2F42B3B70369FC92` | `65C178B284D197CC` | Rivest 1994 |
| RC5-32/12/16 | `5269F149D41BA0152497574D7F153125` | `65C178B284D197CC` | `EB44E415DA319824` | Rivest 1994 |
| RC5-32/0/1 | `00` | `0000000000000000` | `7A7BBA4D79111D1E` | RFC 2040 |
| RC5-32/0/1 | `00` | `FFFFFFFFFFFFFFFF` | `797BBA4D78111D1E` | RFC 2040 |
| RC5-32/1/1 | `11` | `0000000000000000` | `2F759FE7AD86A378` | RFC 2040 |
| RC5-16/16/8 | `0001020304050607` | `00010203` | `23A8D72E` | Krovetz draft |
| RC5-32/20/16 | `000102...0E0F` | `0001020304050607` | `2A0EDC0E9431FF73` | Krovetz draft |
| RC5-64/24/24 | `000102...1617` | `000102...0E0F` | `A46772820EDBCE0235ABEA32AE7178DA` | Krovetz draft |

Blocks are shown as bytes. RC5 words are little-endian, so the paper's first
ciphertext `EEDBA521 6D8F4B15` (two words) is the byte string `21A5DBEE 154B8F6D`.

The other tests cover:

- decryption undoing encryption for 108 parameter combinations (all three
  word sizes, 0 to 255 rounds, 0 to 255 key bytes)
- the magic constants re-derived from *e* and the golden ratio
- rotations, key packing and sub-key table size
- ECB and CBC round trips for every message length, including empty
- a CBC vector from RFC 2040 with a non-zero IV
- padding, wrong keys, and rejection of invalid inputs
- the avalanche effect: one flipped input bit changes about half the output

## Security analysis

**What gives RC5 its strength**

- *Confusion and diffusion* come from mixing three different kinds of
  operation (addition, XOR, rotation) that do not combine in a simple
  algebraic way. `demo.py --section 5` shows the avalanche effect: after about
  4 rounds, flipping one plaintext bit changes close to half of the 64
  ciphertext bits.
- *Data-dependent rotations* were chosen to resist differential and linear
  cryptanalysis, because the attacker cannot predict where bits move.
- *The one-way key schedule* means recovering some sub-keys does not directly
  reveal the key.
- *Adjustable parameters* let the user raise the number of rounds or the key
  length when attacks improve.

**Known attacks**

| Attack | Published by | Result |
|---|---|---|
| Differential cryptanalysis | Biryukov and Kushilevitz, EUROCRYPT 1998 | 12-round RC5-32 broken with 2^44 chosen plaintexts |
| Linear cryptanalysis | Borst, Preneel and Vandewalle, FSE 1999 | Known-plaintext attack on RC5-32 up to 10 rounds, RC5-64 up to 15 |
| Timing attack | Handschuh and Heys, SAC 1998 | If a rotation takes longer for larger amounts, timing leaks sub-key bits |
| Brute force | distributed.net, RSA Secret-Key Challenge | 56-bit key found in 250 days (1997), 64-bit key in 1,757 days (2002); the 72-bit search has run since 2002 and was about 15.7% done in March 2026 |

What this means:

- **12 rounds is no longer a safe margin.** The 2^44 attack is far faster than
  trying 2^128 keys, although it is not practical: 2^44 blocks is about
  128 TiB of chosen plaintext. Sixteen rounds is the usual setting (it is the
  fixed default for IPsec in RFC 2451), and 18 to 20 rounds are often quoted
  as a comfortable margin.
- **Short keys fall to brute force.** `demo.py --section 8` finds a 16-bit key
  in a few seconds. With a 128-bit key, exhaustive search is out of reach.
- **The 64-bit block is the main practical limit.** By the birthday bound,
  CBC ciphertext blocks start to repeat after about 2^32 blocks (32 GiB)
  under one key, which leaks information about the plaintext. RFC 2040
  advises changing the key before that. This is the same weakness behind the
  2016 Sweet32 attack on 3DES and Blowfish. RC5-64 (128-bit block) avoids it.
- **The mode matters as much as the cipher.** ECB leaks patterns
  (`demo.py --section 6`). CBC hides them but gives no integrity: an attacker
  can alter ciphertext without knowing the key, so real systems add a MAC or
  use an authenticated mode.

**Limits of this implementation**

- Python integer operations are not constant-time, so it is open to the
  timing attack above.
- A typed key is used directly as key bytes. A real system would derive the
  key from a password with a slow function such as PBKDF2.
- Keys and sub-keys stay in memory and are not wiped.

For real applications, use a reviewed library and a modern authenticated
cipher such as AES-GCM or ChaCha20-Poly1305.

## Applications

- **Internet standards.** RFC 2040 (1996) defines RC5-CBC, RC5-CBC-Pad and
  RC5-CTS for use in Internet protocols, and RFC 2451 (1998) allows RC5 as an
  encryption algorithm for IPsec ESP.
- **Commercial products.** RSA Security licensed RC5 commercially, and in
  2000 the WAP Forum named it as an encryption algorithm for WTLS, the
  security layer of WAP on early mobile phones.
- **Small devices.** It needs only a short sub-key table and a few lines of
  code. Low memory use, for smart cards and similar devices, was one of
  Rivest's design goals.
- **Measuring brute-force power.** The RSA Secret-Key Challenge (1997 to
  2007) used RC5 ciphertexts as public targets; distributed.net's results are
  a well-known record of how fast key search has become.
- **Successor design.** RC6, one of the five finalists in the AES
  competition, is built directly on RC5.

Today RC5 is mostly of historical and teaching interest. AES replaced it in
new systems. RC5 was patented by RSA Data Security (US 5,724,428); the patent
expired in 2015.

## Acknowledgements

- **Libraries:** none outside the Python standard library. The modules used
  are `os` (random IVs and keys), `argparse`, `sys` and `time` in the demo,
  and `unittest`, `random` and `decimal` in the tests.
- **Algorithm:** the key expansion, encryption and decryption follow the
  pseudo-code in Rivest's paper [1]. No code was copied from another RC5
  implementation.
- **Test vectors:** taken from [1], [2] and [3].
- **AI assistance:** the code and documentation were written with the help of
  Claude, an AI assistant made by Anthropic.

## References

1. R. L. Rivest, "The RC5 Encryption Algorithm", Fast Software Encryption,
   1994. <https://people.csail.mit.edu/rivest/pubs/Riv94.pdf>
2. R. Baldwin and R. Rivest, "The RC5, RC5-CBC, RC5-CBC-Pad, and RC5-CTS
   Algorithms", RFC 2040, 1996. <https://www.rfc-editor.org/rfc/rfc2040.html>
3. T. Krovetz, "RC6 and RC5 Test Vectors for Multiple Block Sizes", IETF
   Internet-Draft.
   <https://datatracker.ietf.org/doc/html/draft-krovetz-rc6-rc5-vectors-00>
4. A. Biryukov and E. Kushilevitz, "Improved Cryptanalysis of RC5",
   EUROCRYPT 1998. <https://doi.org/10.1007/BFb0054119>
5. J. Borst, B. Preneel and J. Vandewalle, "Linear Cryptanalysis of RC5 and
   RC6", FSE 1999. <https://lirias.kuleuven.be/retrieve/333377>
6. H. Handschuh and H. M. Heys, "A Timing Attack on RC5", SAC 1998.
   <https://www.engr.mun.ca/~howard/PAPERS/sac_98.pdf>
7. R. Pereira and R. Adams, "The ESP CBC-Mode Cipher Algorithms", RFC 2451,
   1998. <https://www.rfc-editor.org/rfc/rfc2451.html>
8. distributed.net RC5 projects. <https://en.wikipedia.org/wiki/Distributed.net>
   and <https://en.wikipedia.org/wiki/RSA_Secret-Key_Challenge>
9. "RC5" and "RC6", Wikipedia. <https://en.wikipedia.org/wiki/RC5>,
   <https://en.wikipedia.org/wiki/RC6>
10. "WAP Forum specifies RC5 as an encryption algorithm for WTLS",
    ScanNetSecurity, April 2000 (in Japanese).
    <https://scan.netsecurity.ne.jp/article/2000/04/26/340.html>

## License

MIT. See `LICENSE`.
