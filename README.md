<img src="https://github.com/coignard/qatsi/blob/main/assets/logo.svg?raw=true" alt="Qatsi Logo" height="72">

Hierarchical deterministic key derivation using Argon2id. Generates cryptographically secure mnemonic or alphanumeric secrets without storing anything to disk.

---

**Disclaimer:** Qatsi is not a password manager. It's a hierarchical deterministic key derivation tool I built to solve one specific problem of mine: generating reproducible secrets from a small set of high-entropy master passwords I keep exclusively in memory for high-stakes credentials such as password manager encryption (master passwords, key files), full-disk encryption passphrases, PGP and SSH key passphrases, Proxmox backup encryption keys, and access to critical services where credential loss is unacceptable.

For day-to-day website passwords with varying policies, rotation requirements, and existing credentials, use a traditional password manager like KeePassXC or Bitwarden. Use Qatsi in contexts where you need reproducible secrets across air-gapped systems. See [SECURITY.md](SECURITY.md) for detailed threat model.

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
$ qatsi --mode password --security paranoid
In [0]: ****************
In [1]: 0802BDCD52656EE9 # PGP Key ID
In [2]: Somewhere        # Place created
In [3]:

Out[0]:
3:L;M3ks1ByuQ0d6b-Z*|MDtRKjQ6t:L>YjhXg+@@%emz{|m

Settings:
  ├─ KDF        [✓] Argon2id (m=128 MiB, t=32, p=6)
  ├─ Master     [✓] 16 bytes (16 chars)
  ├─ Layers     [✓] 2 layers
  │  ├─ [✓] In [1]: 16 bytes (16 chars)
  │  └─ [✓] In [2]: 9 bytes (9 chars)
  ├─ PRNG       ChaCha20 (256-bit)
  ├─ Sampling   Unbiased rejection
  └─ Output     48 chars

Stats:
  ├─ Entropy    [✓] 311.6 bits (Paranoid)
  ├─ Length     [✓] 48 chars
  ├─ Charset    90 chars
  └─ Time       4.6s

[✓] Security: Paranoid
```

## How it works

Qatsi combines a master secret with context layers through iterative Argon2id hashing. The final derived key seeds a ChaCha20 stream cipher for unbiased generation of mnemonics or passwords.

Let $K_0 = M$ (master secret as bytes). For each layer $L_i$ with $i \in [1, n]$:

$$K_i = \text{Argon2id}(K_{i-1}, \text{salt}(L_i), m, t, p, \ell)$$

Parameters:

- $K_{i-1}$ — previous derived key (or master secret for $i=1$)
- $\text{salt}(L_i)$ — either $L_i$ directly (if $|L_i| \geq 16$ bytes) or $\text{BLAKE2b-512}(L_i)$
- $m$ — memory cost (in KiB)
- $t$ — number of iterations
- $p$ — parallelism (number of lanes)
- $\ell$ — output length (bytes)

```
 M  ────┐
        ├─── Argon2id(K_0, salt(L_1), m, t, p) ──→ K_1
L_1 ────┘

K_1 ────┐
        ├─── Argon2id(K_1, salt(L_2), m, t, p) ──→ K_2
L_2 ────┘

    ⋮

K_n-1 ──┐
        ├─── Argon2id(K_n-1, salt(L_n), m, t, p) ──→ K_n
L_n ────┘

K_n ──→ ChaCha20(K_n) ──→ Rejection sampling ──→ Output
```

Rejection sampling for mnemonics (7776-word EFF list):

```
Threshold = 65536 - (65536 mod 7776) = 62208

Algorithm:
  1. Sample 16-bit random value r from ChaCha20 keystream
  2. If r < 62208:
       Select word: w = W[r mod 7776]
  3. Else: reject and repeat
```

Rejection sampling for passwords (90-character alphabet):

```
Threshold = 256 - (256 mod 90) = 180

Algorithm:
  1. Sample 8-bit random value b from ChaCha20 keystream
  2. If b < 180:
       Select character: c = A[b mod 90]
  3. Else: reject and repeat
```

This ensures uniform distribution over all words and characters.

### Output entropy

Mnemonics (EFF Large wordlist, 7776 words):

$$E_{\text{mnemonic}} = w \times \log_2(7776) = w \times 12.925 \text{ bits}$$

Where $w$ is the number of words:
- Standard: $w = 8 \Rightarrow E = 103.4 \text{ bits}$
- Paranoid: $w = 24 \Rightarrow E = 310.2 \text{ bits}$

Passwords (90-character alphabet):

$$E_{\text{password}} = \ell \times \log_2(90) = \ell \times 6.492 \text{ bits}$$

Where $\ell$ is the password length:
- Standard: $\ell = 20 \Rightarrow E = 129.8 \text{ bits}$
- Paranoid: $\ell = 48 \Rightarrow E = 311.6 \text{ bits}$

## Security

Argon2id parameters are chosen to resist GPU/ASIC attacks through memory-hardness. All configurations use 256-bit output length and the following settings:

| Profile | Memory | Iterations | Parallelism | Time per hash* |
|---------|--------|------------|-------------|---|
| Standard | 64 MiB | 16 | 6 | ≈0.5s |
| Paranoid | 128 MiB | 32 | 6 | ≈1.25s |

*Time estimates based on NVIDIA Tesla P100 GPU benchmarks (Argon2-gpu-bench). Actual performance varies by hardware.

### Attack cost analysis

For an 80-bit master secret with the paranoid preset (128 MiB, 32 iterations, 6 parallelism):

Expected search (average case, brute-force budget divided by 2):

$$S = 2^{79} \approx 6.0 \times 10^{23} \text{ attempts}$$

Single GPU attack:
- Time per hash: ≈1.25 seconds
- Total time: $2^{79} \times 1.25\text{s} \approx 7.6 \times 10^{23}$ seconds
- Years: $\approx 2.4 \times 10^{16}$ years on a single high-end GPU

500-GPU Cluster attack (linear scaling):

$$T_{500} = \frac{2.4 \times 10^{16}}{500} \approx 4.8 \times 10^{13} \text{ years}$$

With realistic 10% efficiency overhead:

$$T_{500,\text{overhead}} \approx 5.3 \times 10^{13} \text{ years}$$

### Security assumptions

This analysis assumes:

1. Attacker has access to high-end GPUs
2. Cluster is optimally configured with minimal synchronization overhead (realistic clusters may have 5-15% efficiency loss)
3. Master secret has full 80 bits of entropy (must be generated using cryptographically secure RNG, not derived from human input)
4. No advanced attacks on Argon2 have been discovered (current state of cryptanalysis as of 2025)

This security analysis only applies if your master secret has at least 80 bits of true entropy. Weak passphrases (dictionary words, patterns, predictable text, or human-generated passwords) dramatically reduce these estimates and may be cracked in hours or days.

Generate master secrets using `urandom`, `/dev/urandom`, or equivalent cryptographically secure RNG on air-gapped device:

```bash
# Generate a 96-bit random master secret
od -An -tx1 -N12 /dev/urandom | tr -d ' '

# Or 11 random words from the EFF wordlist (≈143 bits)
shuf -n 11 eff_large_wordlist.txt | tr '\n' '-' | sed 's/-$//'
```

### Cryptographic properties

- Automatic memory zeroization via `Zeroizing<T>` for all sensitive data (master secret, layers, salts, derived keys, and generated output)
- EFF Large Wordlist (7776 words) embedded with compile-time SHA-256 integrity verification
- ChaCha20 CSPRNG (256-bit security)
- Unbiased rejection sampling for provably uniform character and word distribution

### Threat model

Protects against offline brute-force attacks, dictionary attacks, GPU/ASIC acceleration, supply-chain attacks (wordlist tampering), and memory disclosure on the host system. It does not provide forward secrecy (a compromised master secret exposes all derived passphrases).

### Design trade-offs

Qatsi is stateless by design. The same inputs always produce the same output. This eliminates entire classes of attacks (vault exfiltration, cloud sync interception, database compromise) but introduces fundamental limitations.

1. Qatsi is not designed for website passwords with varying policies. It's meant for master passwords that unlock other tools (password managers, encrypted vaults, PGP keys) or for secrets in constrained environments (air-gapped systems, live boot USBs). Different sites enforce different requirements: length limits, mandatory symbols, banned characters. Qatsi generates uniform output and cannot adapt per-site without additional context. You can work around this by encoding variations into layers (e.g., `github.com/alphanumeric` vs `github.com/symbols`), but you must remember which variant you used. Traditional password managers store this metadata; Qatsi shifts the burden to you. Use a proper password manager for everyday logins.

2. If a password leaks, you cannot simply regenerate a different one for the same site. Your options are to change the master secret (affecting all passwords) or modify the layer inputs (e.g., append `/v2`), which again requires remembering the modification. Password managers handle rotation trivially by storing independent entries. With Qatsi, rotation means either global changes or tracking mental state about which sites use modified layers.

3. Exposing your master secret compromises every password derivable from it. There's no forward secrecy, no per-password isolation. Traditional managers can at least rotate the vault encryption key or limit exposure to passwords that existed at breach time. With Qatsi, one compromise cascades everywhere. You cannot add 2FA protection to the master secret without storing 2FA state somewhere, defeating the stateless design.

4. If you have accounts with passwords you didn't generate through Qatsi, you must either reset them to Qatsi-generated values or store them elsewhere (undermining the "no storage" premise). Password managers let you gradually migrate by storing both old and new credentials.

Use Qatsi if you prioritize eliminating persistent storage risks and need reproducible secrets across systems. Avoid it if you need to store existing passwords, frequently encounter strict password policies, or require seamless rotation after breaches. See [SECURITY.md](SECURITY.md) for detailed threat model.

## Test

Run the complete test suite:
```bash
cargo test
```

The test suite verifies core correctness guarantees. Determinism tests ensure identical inputs always produce identical outputs across runs and platforms. Regression tests validate known input/output pairs for both standard and paranoid security presets.

Cryptographic primitives are validated through multiple layers. Character set tests confirm exactly 90 unique characters with no duplicates. Wordlist integrity checks verify all 7776 EFF words against their known SHA-256 hash and validate specific word indices. Rejection sampling tests prove statistically unbiased distribution across the entire output space.

Hierarchical key derivation is tested for independence. Different layer combinations produce cryptographically independent keys with no correlation between outputs.

Unicode handling covers normalization and multi-byte characters. Tests verify NFC/NFD equivalence, automatic whitespace trimming, and correct preservation of Cyrillic, CJK ideographs, and emoji sequences.

## License

GPL-3.0
