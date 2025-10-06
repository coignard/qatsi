<img src="https://github.com/coignard/qatsi/blob/main/assets/logo.svg?raw=true" alt="Qatsi Logo" height="72">

Deterministic passphrase generator with layered Argon2id key derivation. Generates cryptographically secure mnemonic or alphanumeric passphrases without storing anything to disk.

---

**Disclaimer:** Qatsi is not a password manager. It's a deterministic secret generator designed for high-entropy master passwords (e.g., KeePassXC database keys), disk encryption passphrases, PGP key passwords, and other secrets that need to be reproduced on-demand without storage.

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

## Quick Start

1. **Install**: `cargo install --git https://github.com/coignard/qatsi`
2. **Run**: `qatsi` (uses default: 8-word mnemonic, standard security)
3. **Enter master secret** when prompted (hidden input)
4. **Enter context layers** (e.g., `github.com`, `2025`, then empty line to finish)
5. **Copy the generated output**

## Usage

### Basic Commands

```bash
# Default: 8-word mnemonic with standard security
qatsi

# 8-word mnemonic (≈103 bits entropy)
qatsi --mode mnemonic --security standard

# 24-word mnemonic (≈310 bits entropy)  
qatsi --mode mnemonic --security paranoid

# 20-character password (≈130 bits entropy)
qatsi --mode password --security standard

# 48-character password (≈312 bits entropy)
qatsi --mode password --security paranoid
```

### Advanced Options

```bash
# Custom word count
qatsi --mode mnemonic --words 12

# Custom password length  
qatsi --mode password --length 32

# Custom KDF parameters (memory in MiB)
qatsi --mode mnemonic --kdf-memory 256 --kdf-iterations 24 --kdf-parallelism 8

# Get help
qatsi --help
```

### Complete CLI Options

- `--mode` / `-m`: `mnemonic` or `password` (default: mnemonic)
- `--security` / `-s`: `standard` or `paranoid` (default: standard)  
- `--words`: Override mnemonic word count (default: 8 for standard, 24 for paranoid)
- `--length`: Override password length (default: 20 for standard, 48 for paranoid)
- `--kdf-memory`: Override KDF memory cost in MiB (default: 64 standard, 128 paranoid)
- `--kdf-iterations`: Override KDF iterations (default: 16 standard, 32 paranoid)
- `--kdf-parallelism`: Override KDF parallelism (default: 6 for both)

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

<br>
<div align="center">
  <img src="https://github.com/coignard/qatsi/blob/main/docs/diagram.png?raw=true" alt="Qatsi Algo Flow" width="512">
</div>
</br>

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

### Design Trade-offs

Qatsi is stateless by design. The same inputs always produce the same output. This eliminates entire classes of attacks (vault exfiltration, cloud sync interception, database compromise) but introduces fundamental limitations.

1. Qatsi is not designed for website passwords with varying policies. It's meant for master passwords that unlock other tools (password managers, encrypted vaults, PGP keys) or for secrets in constrained environments (air-gapped systems, live boot USBs). Different sites enforce different requirements: length limits, mandatory symbols, banned characters. Qatsi generates uniform output and cannot adapt per-site without additional context. You can work around this by encoding variations into layers (e.g., `github.com/alphanumeric` vs `github.com/symbols`), but you must remember which variant you used. Traditional password managers store this metadata; Qatsi shifts the burden to you. Use a proper password manager for everyday logins.

2. If a password leaks, you cannot simply regenerate a different one for the same site. Your options are to change the master secret (affecting all passwords) or modify the layer inputs (e.g., append `/v2`), which again requires remembering the modification. Password managers handle rotation trivially by storing independent entries. With Qatsi, rotation means either global changes or tracking mental state about which sites use modified layers.

3. Exposing your master secret compromises every password derivable from it. There's no forward secrecy, no per-password isolation. Traditional managers can at least rotate the vault encryption key or limit exposure to passwords that existed at breach time. With Qatsi, one compromise cascades everywhere. You cannot add 2FA protection to the master secret without storing 2FA state somewhere, defeating the stateless design.

4. If you have accounts with passwords you didn't generate through Qatsi, you must either reset them to Qatsi-generated values or store them elsewhere (undermining the "no storage" premise). Password managers let you gradually migrate by storing both old and new credentials.

Use Qatsi if you prioritize eliminating persistent storage risks and need reproducible secrets across systems. Avoid it if you need to store existing passwords, frequently encounter strict password policies, or require seamless rotation after breaches. See [SECURITY.md](SECURITY.md) for detailed threat model.

## Common Use Cases

### ✅ Good Use Cases
- **KeePassXC/Bitwarden master passwords**: High-entropy, rarely changed
- **Disk encryption passphrases**: LUKS, BitLocker, FileVault  
- **PGP/GPG key passwords**: Long-term key protection
- **SSH key passphrases**: Securing private keys
- **Air-gapped systems**: Where password managers can't sync
- **Live boot environments**: Tails, forensic tools
- **Server encryption**: Database encryption keys, application secrets

### ❌ Poor Use Cases  
- **Website passwords**: Varying policies, rotation needs
- **API keys**: Often need specific formats  
- **Existing accounts**: Where you can't reset passwords
- **Shared accounts**: Multiple people need access
- **Frequently rotated secrets**: Where you need different passwords over time

## Performance

Expected generation times on modern hardware:

| Hardware | Standard (64 MiB) | Paranoid (128 MiB) |
|----------|-------------------|-------------------|
| M1/M2 Mac | ~0.5s/layer | ~1.0s/layer |
| Intel i7/i9 | ~0.7s/layer | ~1.4s/layer |
| Raspberry Pi 4 | ~3.0s/layer | ~6.0s/layer |

Memory usage scales with KDF settings. Standard preset uses ~64 MiB per layer derivation.

## Troubleshooting

### Installation Issues
```bash
# If cargo install fails, try building from source
git clone https://github.com/coignard/qatsi
cd qatsi
cargo build --release

# Ensure Rust is installed and up to date
rustup update stable
```

### Performance Issues
- **Slow derivation**: Normal for memory-hard KDF. Reduce `--kdf-memory` for faster generation
- **Out of memory**: Lower `--kdf-memory` or use standard preset instead of paranoid
- **Very slow on old hardware**: Consider standard preset or custom parameters

### Input Issues  
- **Unicode characters**: All input is normalized to NFC form and trimmed
- **Control characters**: Will prompt for confirmation if detected
- **Empty layers**: At least one layer required after master secret

## Test

```bash
cargo test
```

Test suite includes:
- Determinism verification (identical inputs → identical outputs)
- Regression tests (known input/output pairs for standard and paranoid presets)
- Character set validation (exactly 90 chars, no duplicates)
- Wordlist integrity (7776 words, SHA-256, known indices)
- Rejection sampling correctness (unbiased distribution)
- Hierarchical chaining (different layer combinations → independent keys)
- Unicode normalization (NFC/NFD equivalence, whitespace trimming)
- Multi-byte Unicode handling (Cyrillic, CJK, emoji preservation)

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
git clone https://github.com/coignard/qatsi
cd qatsi
cargo build
cargo test
cargo clippy  # Fix all warnings
cargo fmt     # Format code
```

### Security Reports
For security vulnerabilities, email `contact@renecoignard.com` instead of opening public issues.

## License

GPL-3.0
