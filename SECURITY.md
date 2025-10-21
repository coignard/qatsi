# Security policy

## Reporting a vulnerability

If you discover a security vulnerability in Qatsi, please report it via GitHub Security Advisories:

**[Report a vulnerability](https://github.com/coignard/qatsi/security/advisories/new)**

Do not open a public issue or email the maintainers directly.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response time

- Initial response: 48 hours
- Fix timeline: 7-14 days (depending on severity)

GitHub Security Advisories provide a private communication channel and allow coordinated disclosure before public patching.

## Cryptographic primitives

All components use standard, well-analyzed primitives:

- Argon2id (RFC 9106): memory-hard KDF, 256-bit output
- BLAKE2b-512 (RFC 7693): salt preprocessing for inputs shorter than 16 bytes
- ChaCha20 (RFC 8439): stream cipher for keystream generation
- EFF Large Wordlist: 7776 words, SHA-256 verified at compile-time

### Memory safety

Implementation in Rust uses `Zeroizing<T>` wrapper (crate `zeroize`) for automatic secure erasure of all sensitive data:

- Master secret
- Layer inputs
- Salts
- Derived keys
- Generated output

All sensitive data is automatically cleared on drop with panic-safe volatile writes preventing compiler optimization removal.

### Unicode Normalization

All text inputs undergo Unicode Normalization Form C (NFC) and leading/trailing whitespace trimming to ensure consistent byte representation regardless of input method (composed vs decomposed forms).

### Wordlist integrity

Compile-time verification prevents supply-chain attacks. The embedded EFF Large Wordlist is verified against its known SHA-256 hash during build. Tampering causes compilation failure.

Expected hash: `addd3553...96b903e` (64 hex digits)

Known indices verified at build time:
- `W[0]` = "abacus"
- `W[469]` = "balance"
- `W[3695]` = "life"
- `W[7775]` = "zoom"

## Attack resistance

### Brute-force resistance

For master secret entropy $e$ bits and Argon2id configuration $(m, t, p)$ with processing time $\tau$ seconds per hash, average-case brute-force time to recover secret:

$$T_{\text{attack}} = 2^{e-1} \cdot \tau$$

For $e = 80$ bits (recommended minimum):

$$T_{\text{attack}} = 2^{79} \cdot \tau \approx 6.04 \times 10^{23} \cdot \tau \text{ seconds}$$

### Conservative GPU estimates

High-end GPUs (NVIDIA A100, H100) optimized for Argon2 achieve estimated $\tau \approx 1.25$ s for Paranoid configuration (128 MiB, $t=32$, $p=6$):

Single-GPU attack:

$$T_{\text{single}} = 2^{79} \times 1.25 \text{ s} \approx 7.56 \times 10^{23} \text{ s} \approx 2.39 \times 10^{16} \text{ years}$$

500-GPU cluster with 10% coordination overhead:

$$T_{500} = \frac{2.39 \times 10^{16}}{500} \times 1.1 \approx 5.27 \times 10^{13} \text{ years}$$

### Memory-bound parallelism

The critical security property is not computational speed but memory requirements. A GPU with 40 GB RAM can maintain at most $\lfloor 40000 / 128 \rfloor = 312$ parallel Argon2 instances. Even with 500 such GPUs (156,000 parallel attempts):

$$T_{\text{parallel}} = \frac{2^{79}}{156000} \times 1.25 \text{ s} \approx 4.84 \times 10^{18} \text{ s} \approx 1.53 \times 10^{11} \text{ years}$$

This remains computationally infeasible (153 billion years) even with massive parallelization, validating memory-hardness as the primary defense mechanism.

### Hardware attack benchmarks

Actual Argon2id performance on representative hardware:

| Platform | Standard (ms) | Paranoid (ms) |
|----------|---------------|---------------|
| Apple M1 Pro (2021)† | 544 | 2273 |
| NVIDIA A100 (est.)‡ | 250 | 1000 |
| NVIDIA H100 (est.)‡ | 150 | 625 |

†Measured (median of 5 runs).
‡Estimated based on memory bandwidth and published Argon2 benchmarks.

M1 Pro measurements ($\tau = 2.273$ s for Paranoid) are 1.8× slower than conservative GPU estimate ($\tau = 1.25$ s), confirming attack cost estimates are realistic lower bounds. The memory-hard property ensures even specialized hardware cannot achieve orders-of-magnitude speedups without proportional memory increases.

### Master secret entropy requirements

| Source | Entropy (bits) | Status |
|--------|----------------|--------|
| 16-byte `/dev/urandom` | 128 | Secure |
| 11 EFF words | ≈142 | Secure |
| 80-bit CSPRNG | 80 | Minimum* |
| Human password | <40 | Insufficient |

*80-bit minimum provides $\approx 2.4 \times 10^{16}$ year resistance against single-GPU attacks under Paranoid configuration.

### Generating master secrets

Master secrets must be generated using a cryptographically secure pseudorandom number generator (CSPRNG). Human-generated passwords or dictionary words do not provide sufficient entropy.

96-bit random master secret (12 bytes):

```bash
od -An -tx1 -N12 /dev/urandom | tr -d ' '
```

11 EFF words (~142 bits):

```bash
shuf -n 11 eff_large_wordlist.txt | tr '\n' '-' | sed 's/-$//'
```

## Threat model

### Adversarial capabilities

We consider an adversary $\mathcal{A}$ with:

1. Offline brute-force: $\mathcal{A}$ can compute Argon2id hashes on custom hardware (GPUs, ASICs) with full parameter knowledge.
2. Memory access: $\mathcal{A}$ observes all derived outputs but not intermediate keys.
3. Layer knowledge: $\mathcal{A}$ knows all layer strings (Kerckhoffs's principle).
4. Computational bound: $\mathcal{A}$ has access to $p$ parallel processors with memory $M$ GB each.

### Out of scope

The following threats are explicitly out of scope:

- Keyloggers during input
- Side-channel timing attacks
- Quantum adversaries (Grover's algorithm provides only $\sqrt{2}$ speedup)
- Physical coercion
- Social engineering
- Screen capture or visual observation during input
- Terminal history leaks (master secret in shell history)
- Compromised binaries (if the `qatsi` executable is replaced with malware)

### Protection guarantees

Qatsi protects against:

- Offline brute-force attacks (memory-hard KDF)
- Dictionary attacks (high-entropy master secret requirement)
- GPU/ASIC parallelization (memory-hardness limits concurrent attempts)
- Supply-chain attacks (compile-time wordlist integrity verification)
- Vault exfiltration (no vault exists)
- Cloud interception (no synchronization)
- Database compromise (no database exists)
- Memory disclosure on host system (automatic zeroization)

### Limitations

Qatsi does not protect against:

- Master secret compromise: If the master secret is exposed, all derived secrets are compromised. There is no key isolation.
- Side-channel attacks: No constant-time guarantees. Timing attacks, cache attacks, and power analysis are not mitigated.
- Input observation: Keyloggers, screen capture, or shoulder surfing during master secret entry.
- Quantum adversaries: Grover's algorithm reduces effective security by half (80-bit entropy becomes 40-bit resistance).

## Design limitations

### No key isolation

Master secret compromise exposes all derived secrets. Unlike vault-based managers where individual credential leaks remain isolated, deterministic derivation creates dependency on a single root secret. This is inherent to stateless deterministic systems.

### No credential rotation isolation

Changing a single derived secret requires either:

1. Modifying layer inputs (user must remember modification)
2. Changing master secret (affects all derivations)

Traditional password managers handle rotation trivially by storing independent entries.

### Layer enumeration

Predictable layer patterns (e.g., `service/YYYY`) enable targeted enumeration. Mitigation: use high-entropy layer strings documented separately from master secret.

### Cannot import existing passwords

If you have passwords not generated by Qatsi, you must either reset them to Qatsi-generated values or store them elsewhere (undermining the stateless design).

## Use cases

### Appropriate use cases

Qatsi is designed for:

- Password manager master passwords (KeePassXC, Bitwarden)
- Full-disk encryption passphrases (LUKS, BitLocker, FileVault)
- PGP/SSH key passphrases
- Cryptocurrency wallet encryption passphrases
- Critical service credentials on air-gapped systems

### Inappropriate use cases

Qatsi is not suitable for:

- General website passwords (varying policies, frequent rotation)
- Existing credentials (API keys, legacy passwords)
- Multi-device sync with conflict resolution
- Scenarios requiring key isolation after breach

Qatsi targets high-stakes reproducible secrets in constrained environments where stateless reproducibility outweighs rotation flexibility.

## Configuration profiles

| Profile | Memory (MiB) | Iterations | Parallelism | M1 Pro Time* |
|---------|--------------|------------|-------------|--------------|
| Standard | 64 | 16 | 6 | 544 ms |
| Paranoid | 128 | 32 | 6 | 2273 ms |

*Measured on Apple M1 Pro (2021), median of 5 runs, single-layer derivation.

Output length fixed at 32 bytes (256 bits) for compatibility with ChaCha20.

## Comparison with existing approaches

| Property | KeePassXC | BIP39 | Diceware | Qatsi |
|----------|-----------|-------|----------|-------|
| Storage | Vault | None | None | None |
| KDF | Argon2/AES | PBKDF2 | N/A | Argon2id |
| Hierarchical | No | No | No | Yes |
| Memory-hard | Yes | No | N/A | Yes |
| Rotation | Easy | Hard | Hard | Hard |
| Key isolation | Yes | No | No | No |

## Known issues

- No constant-time operations: Side-channel attacks are not specifically mitigated
- No input rate limiting: Repeated derivation attempts are not throttled (by design, for offline use)
- No protection against compromised binaries: If the `qatsi` executable is replaced with malware, it can log your master secret

## Dependencies

Security-critical dependencies (all from RustCrypto project):

- `argon2 = "0.5.3"` (Argon2id implementation)
- `chacha20 = "0.9.1"` (ChaCha20 stream cipher)
- `blake2 = "0.10.6"` (BLAKE2b for salt expansion)
- `zeroize = "1.8.2"` (Memory zeroization)

All dependencies are widely-used, actively-maintained crates.

## Operational security

### Layer design

Use high-entropy, non-obvious strings. Avoid sequential numbers or dictionary words. Document layers separately from master secret in offline storage.

### Backup

Maintain physical copy of master secret in secure location (safe, bank deposit box). Loss is unrecoverable. Consider Shamir's Secret Sharing for distributed backup.

## Audit status

No formal security audit has been conducted. The codebase is open-source and community review is welcome. See the [technical report](paper/qatsi-technical-report.pdf) for formal cryptographic analysis with proofs of output uniformity, GPU attack cost quantification, and detailed security analysis.
