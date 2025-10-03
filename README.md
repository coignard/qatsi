<img src="https://github.com/coignard/qatsi/blob/main/assets/logo.svg?raw=true" alt="Qatsi Logo" height="72">

Hierarchical deterministic passphrase generator using hierarchical Argon2id key derivation. Generates cryptographically secure mnemonic or alphanumeric passphrases without storing anything to disk.

Designed for master passwords and other high-entropy secrets that need to be reproduced on-demand from a master secret and context layers.

## Install

```bash
cargo install --git https://github.com/coignard/qatsi
```

Or build from source:

```bash
git clone https://github.com/coignard/qatsi
cd qatsi
cargo build --release
sudo cp target/release/qatsi /usr/local/bin/
```

## Usage

```bash
# 8-word mnemonic (≈103 bits entropy)
qatsi --mode mnemonic --security standard

# 24-word mnemonic (≈310 bits entropy)
qatsi --mode mnemonic --security paranoid

# 20-character password (≈130 bits entropy)
qatsi --mode password --security standard

# 48-character password (≈312 bits entropy)
qatsi --mode password --security paranoid
```

You can override the default security presets with custom parameters for fine-grained control:

```bash
# Generate a 12-word mnemonic with custom KDF memory (256 MiB)
qatsi --mode mnemonic --words 12 --kdf-memory 256

# Generate a 32-character password with custom KDF iterations
qatsi --mode password --length 32 --kdf-iterations 24
```

Example usage:

```
$ qatsi

In [0]: *************
In [1]: github.com
In [2]: 2025
In [3]:

Out[0]:
possum-record-distinct-rekindle-fiftieth-unwanted-removal-security

Settings:
  ├─ KDF        [✓] Argon2id (m=64 MiB, t=16, p=6)
  ├─ Master     [✓] 28 bytes (28 chars)
  ├─ Layers     [✓] 2 layers
  │  ├─ [✓] In [1]: 10 bytes (10 chars)
  │  └─ [✓] In [2]: 4 bytes (4 chars)
  ├─ PRNG       ChaCha20 (256-bit)
  ├─ Sampling   Unbiased rejection
  └─ Output     8 words

Stats:
  ├─ Entropy    [✓] 103.4 bits (Strong)
  ├─ Length     [✓] 61 chars
  ├─ Words      [✓] 8 words
  ├─ Wordlist   EFF Large (7776 words)
  └─ Time       0.5s

[✓] Security: Strong
```

## How it works

The core of `qatsi` is a hierarchical key derivation process. The following diagram illustrates the flow from user input to the final generated output:

<img src="https://github.com/coignard/qatsi/blob/main/docs/diagram.png?raw=true" alt="Qatsi Algo Flow">

Given master secret $M$ and context layers $L_1, \ldots, L_n$, hierarchical key derivation:

$$K_0 = M$$

$$K_i = \text{Argon2id}(K_{i-1}, \text{salt}(L_i), m, t, p, \ell) \quad \forall i \in [1, n]$$

**Configurations:**

| Profile | Memory | Iterations | Parallelism | Time (M1 Pro) |
|---------|--------|------------|-------------|---------------|
| Standard | 64 MiB | 16 | 6 threads | ~0.5s/layer |
| Paranoid | 128 MiB | 32 | 6 threads | ~1.0s/layer |

**Output entropy:**

- Mnemonic: $w \times \log_2(7776) \approx w \times 12.925$ bits, where $w \in \{8, 24\}$
- Password: $\ell \times \log_2(90) \approx \ell \times 6.492$ bits, where $\ell \in \{20, 48\}$

The final key $K_n$ seeds a ChaCha20 stream cipher for unbiased rejection sampling:

- Mnemonic: Reject if random $u16 \geq 65535 - (65535 \pmod{7776})$ (ensures uniform selection from 7776 words)
- Password: Reject if random byte $\geq 256 - (256 \pmod{90})$ (ensures uniform selection from 90-character alphabet)

## Security

**Argon2id parameters** are chosen to resist GPU/ASIC attacks through memory-hardness:

- Standard: 64 MiB memory, 16 iterations, 6-thread parallelism
- Paranoid: 128 MiB memory, 32 iterations, 6-thread parallelism

**Attack resistance:** For an 80-bit master secret with the paranoid preset, the expected brute-force time exceeds $3.8 \times 10^8$ years on a cluster of 500 high-end GPUs, each attempting 100 hashes per second.

**Cryptographic properties:**

- Automatic memory zeroization via `Zeroizing<T>` for all sensitive data (master secret, layers, salts, derived keys, and generated output).
- EFF Large Wordlist (7776 words) embedded with compile-time SHA-256 integrity verification
- ChaCha20 CSPRNG (256-bit security)
- Unbiased rejection sampling for provably uniform character and word distribution

**Threat model:** Protects against offline brute-force attacks, dictionary attacks, GPU/ASIC acceleration, supply-chain attacks (wordlist tampering), and memory disclosure on the host system. It does not provide forward secrecy (a compromised master secret exposes all derived passphrases).

## Test

```bash
cargo test
```

Test suite includes:
- Determinism verification (identical inputs → identical outputs)
- Wordlist integrity (7776 words, SHA-256, known indices)
- Rejection sampling correctness
- Different layer combinations produce independent keys
- Character set validation (exactly 90 chars)

## License

GPL-3.0
