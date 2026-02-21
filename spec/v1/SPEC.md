# Universal Quantum Seed — Specification v1

**Status:** Active
**Version:** 1.0
**Domain separator:** `universal-seed-v1`

> **Compatibility contract:** v1 seeds MUST always derive the same outputs forever.
> No parameter may be changed within v1. If parameters change, a new version (v2+)
> with a new domain separator and spec folder MUST be created. Never "tune Argon2"
> or adjust PBKDF2 rounds inside v1.

---

## 1. Overview

The Universal Quantum Seed generates cryptographically secure seeds using 256 visual icons
(8 bits each), derives hardened master keys through a 6-layer KDF pipeline, and supports
post-quantum signature key generation via NIST FIPS 204 (ML-DSA-65) and FIPS 205
(SLH-DSA-SHAKE-128s).

| Property | Value |
|:---|:---|
| Word counts | 24 (classical) or 36 (quantum-safe) |
| Data words | 22 (classical) or 34 (quantum-safe) |
| Checksum words | 2 (last two positions) |
| Entropy | 24 words = 176-bit (classical), 36 words = 272-bit (quantum-safe) |
| Post-quantum security | 24 words = 88-bit, 36 words = 136-bit (Grover) |
| Checksum | 16-bit HMAC-SHA-256 (1-in-65,536 error detection) |
| Fingerprint | 8-char hex (4 bytes = 32 bits) |
| Domain separator | `b"universal-seed-v1"` |
| Icon set | 256 icons, indexed 0-255 |
| Post-quantum | ML-DSA-65 (FIPS 204) + SLH-DSA-SHAKE-128s (FIPS 205) |

---

## 2. Icon-Index Mapping

Each index (0-255) maps to exactly one icon. Icons are identified by their index, not by
filename. Filenames are cosmetic; the index is authoritative.

The canonical icon assets are in `visuals/` (256x256 PNG + SVG, Fluent Emoji flat style).
If icons are re-rendered, the index mapping MUST NOT change.

Base word list (index 0-255):
```
  0: eye       1: ear       2: nose      3: mouth     4: tongue    5: bone
  6: tooth     7: skull     8: heart     9: brain    10: baby     11: foot
 12: muscle   13: hand     14: leg      15: dog      16: cat      17: horse
 18: cow      19: pig      20: goat     21: rabbit   22: mouse    23: tiger
 24: wolf     25: bear     26: squirrel 27: deer     28: elephant  29: bat
 30: camel    31: zebra    32: giraffe  33: fox      34: lion     35: monkey
 36: panda    37: llama    38: chicken  39: bird     40: duck     41: penguin
 42: peacock  43: owl      44: eagle    45: snake    46: frog     47: turtle
 48: crocodile 49: lizard  50: fish     51: octopus  52: crab     53: whale
 54: dolphin  55: shark    56: snail    57: ant      58: bee      59: butterfly
 60: worm     61: spider   62: scorpion 63: sun      64: moon     65: star
 66: earth    67: fire     68: water    69: snow     70: cloud    71: rainbow
 72: wind     73: thunder  74: volcano  75: tornado  76: comet    77: wave
 78: rain     79: desert   80: island   81: mountain 82: rock     83: diamond
 84: feather  85: tree     86: cactus   87: flower   88: leaf     89: mushroom
 90: wood     91: mango    92: apple    93: banana   94: grape    95: orange
 96: melon    97: peach    98: pineapple 99: cherry 100: lemon   101: coconut
102: cucumber 103: seed   104: strawberry 105: corn  106: carrot  107: onion
108: potato  109: pepper  110: tomato  111: garlic  112: peanut  113: bread
114: cheese  115: egg     116: meat    117: rice    118: cake    119: snack
120: sweet   121: honey   122: milk    123: coffee  124: tea     125: wine
126: beer    127: juice   128: salt    129: fork    130: spoon   131: bowl
132: knife   133: bottle  134: soup    135: pan     136: key     137: lock
138: bell    139: hammer  140: axe     141: gear    142: magnet  143: sword
144: bow     145: compass 146: hook    147: thread  148: needle  149: scissors
150: pencil  151: shield  152: bomb    153: house   154: castle  155: temple
156: bridge  157: factory 158: door    159: window  160: tent    161: beach
162: bank    163: tower   164: statue  165: wheel   166: boat    167: train
168: car     169: bike    170: plane   171: rocket  172: helicopter 173: ambulance
174: fuel    175: track   176: map     177: drum    178: guitar  179: violin
180: piano   181: paint   182: book    183: mask    184: camera  185: microphone
186: headset 187: movie   188: music   189: dress   190: coat    191: pants
192: glove   193: shirt   194: shoes   195: hat     196: flag    197: cross
198: circle  199: triangle 200: square 201: check   202: alert   203: sleep
204: magic   205: message 206: blood   207: repeat  208: dna     209: germ
210: pill    211: doctor  212: microscope 213: galaxy 214: flask  215: atom
216: satellite 217: battery 218: telescope 219: tv   220: radio   221: phone
222: bulb    223: keyboard 224: chair  225: bed     226: candle  227: mirror
228: ladder  229: basket  230: vase    231: shower  232: razor   233: soap
234: computer 235: trash  236: umbrella 237: money  238: prayer  239: toy
240: crown   241: ring    242: dice    243: piece   244: coin    245: calendar
246: boxing  247: swimming 248: game   249: soccer  250: ghost   251: alien
252: robot   253: angel   254: dragon  255: clock
```

---

## 3. Encoding

A seed is an ordered list of N icon indexes where:
- First N-2 indexes are **data** (random entropy)
- Last 2 indexes are **checksum** (derived from data)

```
full_seed = [data_0, data_1, ..., data_{N-3}, checksum_0, checksum_1]
```

- 24 words: 22 data bytes + 2 checksum = 176 bits of entropy (classical tier)
- 36 words: 34 data bytes + 2 checksum = 272 bits of entropy (quantum-safe tier)

---

## 4. Checksum

The checksum is computed via HMAC-SHA-256 with domain separation:

```python
def compute_checksum(data_indexes):
    key = b"universal-seed-v1-checksum"
    message = bytes(data_indexes)
    digest = HMAC-SHA256(key, message)
    return [digest[0], digest[1]]
```

| Property | Value |
|:---|:---|
| Algorithm | HMAC-SHA-256 |
| Key | `b"universal-seed-v1-checksum"` (25 bytes) |
| Message | data indexes as raw bytes |
| Output | First 2 bytes of HMAC digest |
| Error detection | 16 bits (1-in-65,536 false positive) |

### Verification

```python
def verify_checksum(full_indexes):
    if len(full_indexes) not in (24, 36):
        return False
    data = full_indexes[:-2]
    expected = compute_checksum(data)
    return full_indexes[-2:] == expected
```

---

## 5. Passphrase Normalization

Passphrases are **raw UTF-8 bytes with no normalization**.

```python
passphrase_bytes = passphrase_string.encode("utf-8")
```

- No NFKC/NFC normalization
- No whitespace trimming or case folding
- Empty string `""` is equivalent to no passphrase

---

## 6. Key Derivation Pipeline (6 layers)

### 6.0 Checksum Verification & Stripping

Before any KDF computation:
1. Verify the seed has exactly 24 or 36 indexes
2. Verify the last 2 indexes match `compute_checksum(indexes[:-2])`
3. Strip the checksum: `data_indexes = indexes[:-2]`

If verification fails, key derivation MUST be rejected with an error.

### 6.1 Positional Binding

Each data icon index is packed with its zero-based position as a little-endian (pos, index) byte pair:

```python
payload = b""
for pos, idx in enumerate(data_indexes):
    payload += struct.pack("<BB", pos, idx)
```

This binds each icon to its slot, preventing reordering attacks.

### 6.2 Passphrase Mixing

If a passphrase is provided, its raw UTF-8 bytes are appended:

```python
if passphrase:
    payload += passphrase.encode("utf-8")
```

### 6.3 HKDF-Extract (RFC 5869)

The payload is collapsed into a pseudorandom key (PRK) using HMAC-SHA512:

```python
prk = HMAC-SHA512(key=b"universal-seed-v1", message=payload)
```

- Key: domain separator `b"universal-seed-v1"` (17 bytes)
- Message: positional payload + optional passphrase bytes
- Output: 64 bytes (512 bits)

### 6.4 Chained KDF Stretching

The PRK is hardened through two KDFs in series:

**Stage 1: PBKDF2-SHA512**
```
salt    = b"universal-seed-v1-stretch-pbkdf2"
rounds  = 600,000
dklen   = 64 bytes
output  = PBKDF2-SHA512(prk, salt, rounds, dklen)
```

**Stage 2: Argon2id**
```
secret      = stage1_output (64 bytes)
salt        = b"universal-seed-v1-stretch-argon2id"
time_cost   = 3
memory_cost = 65536 (64 MiB)
parallelism = 4
hash_len    = 64 bytes
type        = Argon2id
```

### 6.5 HKDF-Expand (RFC 5869)

Final key derivation with domain separation:

```
info    = b"universal-seed-v1-master"
length  = 64 bytes
output  = HKDF-Expand-SHA512(stretched, info, 64)
```

HKDF-Expand implementation:
```python
def hkdf_expand(prk, info, length):
    n = ceil(length / 64)
    okm = b""
    prev = b""
    for i in range(1, n + 1):
        prev = HMAC-SHA512(key=prk, message=prev + info + bytes([i]))
        okm += prev
    return okm[:length]
```

### 6.6 Output

The final output is **64 bytes (512 bits)** of key material:
- First 32 bytes: 256-bit encryption key
- Last 32 bytes: 256-bit authentication key
- Or used whole as a master seed for further derivation

---

## 7. Profile Derivation

The master seed can derive unlimited independent **profile keys** using profile passwords.
Each password produces a completely unrelated key. Without the password, a profile's
existence cannot be detected (plausible deniability).

```python
def get_profile(master_key, profile_password):
    if not profile_password:
        return master_key  # empty = default profile
    payload = b"universal-seed-v1-profile" + profile_password.encode("utf-8")
    return HMAC-SHA512(key=master_key, message=payload)
```

| Property | Value |
|:---|:---|
| Algorithm | HMAC-SHA512 |
| Key | master seed (64 bytes from KDF pipeline) |
| Message | `b"universal-seed-v1-profile"` + password UTF-8 bytes |
| Output | 64 bytes (512 bits) |
| Empty password | Returns master seed unchanged (default profile) |
| Speed | Instant (single HMAC, no KDF) |

### Properties

- **Deterministic** — same master seed + same password always produces the same profile key
- **Independent** — profiles cannot be derived from each other
- **Hidden** — no way to enumerate how many profiles exist
- **Plausible deniability** — under duress, reveal only the default profile
- **No limit** — unlimited profiles from a single master seed

---

## 8. Fingerprint

**Without passphrase** (instant):
```python
payload = positional_payload(data_indexes)  # checksum already stripped
key = HMAC-SHA512(key=b"universal-seed-v1", message=payload)
fingerprint = key[0:4].hex().upper()   # 8-char hex, e.g. "0FBFBBCB"
```

**With passphrase** (runs full KDF):
```python
key = get_seed(full_seed, passphrase)  # verifies + strips checksum internally
fingerprint = key[0:4].hex().upper()
```

| Property | Value |
|:---|:---|
| Length | 8 hex characters (4 bytes = 32 bits) |
| Format | Uppercase hex, e.g. `"0FBFBBCB"` |
| Derived from | Data indexes only (checksum stripped) |

---

## 9. Post-Quantum Key Derivation

The master seed can derive post-quantum keypairs via HKDF-Expand with algorithm-specific
domain separation. This ensures complete independence between classical keys and each
quantum algorithm's keys.

> **The 36-word seed format (272-bit) is required for post-quantum key derivation.**
> ML-DSA-65 (NIST Level 3) requires at least 192-bit entropy; the 24-word format (176-bit)
> does not meet this threshold. Implementations SHOULD enforce the 36-word minimum when
> deriving quantum keypairs.

### 9.1 Quantum Seed Derivation

```python
_QUANTUM_SEED_SIZES = {
    "ml-dsa-65": 32,            # xi seed for FIPS 204 KeyGen
    "slh-dsa-shake-128s": 48,   # SK.seed(16) + SK.prf(16) + PK.seed(16)
}

def get_quantum_seed(master_key, algorithm, key_index=0):
    size = _QUANTUM_SEED_SIZES[algorithm]
    info = b"universal-seed-v1-quantum-" + algorithm.encode("ascii") + pack("<I", key_index)
    return hkdf_expand(master_key, info, size)
```

| Algorithm | Seed Size | Info String |
|:---|:---:|:---|
| ML-DSA-65 | 32 bytes | `b"universal-seed-v1-quantum-ml-dsa-65"` + key_index (4 bytes LE) |
| SLH-DSA-SHAKE-128s | 48 bytes | `b"universal-seed-v1-quantum-slh-dsa-shake-128s"` + key_index (4 bytes LE) |

### 9.2 ML-DSA-65 (FIPS 204)

Lattice-based digital signature — NIST Security Level 3 (192-bit post-quantum).

| Property | Value |
|:---|:---|
| Standard | FIPS 204 |
| Public key | 1,952 bytes |
| Secret key | 4,032 bytes |
| Signature | 3,309 bytes |
| Assumption | Module Learning With Errors (MLWE) |
| Dependencies | SHAKE-128, SHAKE-256, SHA-256/512 |

### 9.3 SLH-DSA-SHAKE-128s (FIPS 205)

Hash-based digital signature — NIST Security Level 1 (128-bit post-quantum).

| Property | Value |
|:---|:---|
| Standard | FIPS 205 |
| Public key | 32 bytes |
| Secret key | 64 bytes |
| Signature | 7,856 bytes |
| Assumption | Hash-only (SHAKE-256) |
| Dependencies | SHAKE-256 only |

### 9.4 Properties

- **Deterministic** — same master seed + algorithm + key_index always produces the same keypair
- **Independent** — ML-DSA and SLH-DSA keys are completely independent from each other and from classical keys
- **Domain separated** — distinct HKDF info strings prevent cross-algorithm key reuse
- **Expandable** — key_index allows multiple keypairs per algorithm

---

## 10. Word Resolution

### Strict Mode (used in key derivation)

`_to_indexes()` uses `resolve(words, strict=True)`:
- NFKC normalization + lowercase
- Exact lookup table match only
- Emoji variation selector stripping
- **No fuzzy fallbacks** (no diacritics, no articles, no suffixes)

### Fuzzy Mode (used in UI/recovery)

`resolve(words, strict=False)` (default) tries fallbacks:
1. Diacritic stripping (Latin, Greek, Arabic, Hebrew, Cyrillic)
2. Arabic prefix stripping
3. Hebrew prefix stripping
4. French/Italian contraction stripping
5. Scandinavian/Romanian/Icelandic suffix stripping

Fuzzy mode is for user convenience during recovery. The checksum catches any misresolution.

---

## 11. Security Notes

### Quantum safety

The entire symmetric pipeline (SHA-512, HKDF, PBKDF2, Argon2id) is quantum-safe.
Grover's algorithm only halves the security bits:

| Format | Entropy | Post-Quantum (Grover) | NIST Level |
|:---|:---:|:---:|:---|
| 36 words | 272-bit | 136-bit | Exceeds Level 5 |
| 24 words | 176-bit | 88-bit | Below Level 1 |

**The 36-word format is required for quantum-safe applications.** Its 136-bit post-quantum
security exceeds ML-DSA-65's Level 3 requirement (96-bit PQ) and the 128-bit security floor.
The 24-word format provides strong classical security but should not be used for post-quantum
key derivation.

The quantum signature algorithms (ML-DSA-65, SLH-DSA-SHAKE-128s) provide quantum-safe
digital signatures for use cases where classical ECC (secp256k1, Ed25519) will be
broken by Shor's algorithm.

### Protected against
- Brute-force (272-bit entropy + chained KDF)
- GPU/ASIC attacks (Argon2id memory-hardness)
- Reordering attacks (positional binding)
- Transcription errors (16-bit checksum)
- Weak RNG (8 independent entropy sources, validated before use)
- Fuzzy misresolution in KDF (strict mode)
- Quantum computers (symmetric crypto + quantum signatures)

### NOT protected against
- Physical seed theft (paper backup compromise)
- Keylogger capturing passphrase
- Compromised implementation (supply chain)
- Social engineering

---

## 12. Verification Signals

v1 provides two independent verification signals:

| Signal | Bits | Derived from | When available |
|:---|:---:|:---|:---|
| Checksum (last 2 words) | 16 | Data indexes via HMAC-SHA-256 | Always (built into seed) |
| Fingerprint | 32 | Data indexes via HMAC-SHA-512 (or full KDF with passphrase) | After resolution |

Both MUST be specified and implemented. The fingerprint changes with passphrase; the checksum does not.
