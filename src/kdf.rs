use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::{Blake2b512, Digest};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy)]
pub struct Argon2Config {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Config {
    pub const STANDARD: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 16,
        parallelism: 6,
    };

    pub const PARANOID: Self = Self {
        memory_kib: 128 * 1024,
        iterations: 32,
        parallelism: 6,
    };

    pub fn memory_mib(&self) -> u32 {
        self.memory_kib / 1024
    }
}

const OUTPUT_LEN: usize = 32;
const MIN_SALT_LEN: usize = 8;

pub fn derive_hierarchical(
    master_secret: &[u8],
    layers: &[String],
    config: Argon2Config,
) -> Result<Zeroizing<[u8; OUTPUT_LEN]>> {
    let params = Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(OUTPUT_LEN),
    )
    .context("Failed to create Argon2 parameters")?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut current_key = Zeroizing::new([0u8; OUTPUT_LEN]);

    derive_single(
        &argon2,
        master_secret,
        layers[0].as_bytes(),
        &mut current_key,
    )
    .context("Failed to derive key from master secret")?;

    for (i, layer) in layers[1..].iter().enumerate() {
        let mut next_key = Zeroizing::new([0u8; OUTPUT_LEN]);
        derive_single(&argon2, &current_key[..], layer.as_bytes(), &mut next_key)
            .with_context(|| format!("Failed to derive key at layer {}", i + 2))?;
        current_key = next_key;
    }

    Ok(current_key)
}

fn derive_single(
    argon2: &Argon2,
    password: &[u8],
    salt_input: &[u8],
    output: &mut [u8; OUTPUT_LEN],
) -> Result<()> {
    let salt: Vec<u8> = if salt_input.len() >= MIN_SALT_LEN {
        salt_input.to_vec()
    } else {
        let mut hasher = Blake2b512::new();
        hasher.update(salt_input);
        hasher.finalize().to_vec()
    };

    argon2
        .hash_password_into(password, &salt, output)
        .map_err(|e| anyhow::anyhow!("Argon2 derivation failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_derivation() {
        let master = b"test_master_secret";
        let layers = vec!["layer1".to_string(), "layer2".to_string()];

        let key1 = derive_hierarchical(master, &layers, Argon2Config::STANDARD).unwrap();
        let key2 = derive_hierarchical(master, &layers, Argon2Config::STANDARD).unwrap();

        assert_eq!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_different_configs_different_keys() {
        let master = b"test_master_secret";
        let layers = vec!["layer1".to_string()];

        let key_standard = derive_hierarchical(master, &layers, Argon2Config::STANDARD).unwrap();
        let key_paranoid = derive_hierarchical(master, &layers, Argon2Config::PARANOID).unwrap();

        assert_ne!(key_standard.as_ref(), key_paranoid.as_ref());
    }

    #[test]
    fn test_different_layers_different_keys() {
        let master = b"test_master_secret";
        let layers1 = vec!["layer1".to_string()];
        let layers2 = vec!["layer2".to_string()];

        let key1 = derive_hierarchical(master, &layers1, Argon2Config::STANDARD).unwrap();
        let key2 = derive_hierarchical(master, &layers2, Argon2Config::STANDARD).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_hierarchical_chaining() {
        let master = b"test_master_secret";
        let layers_full = vec!["layer1".to_string(), "layer2".to_string()];
        let layers_partial = vec!["layer1".to_string()];

        let key_full = derive_hierarchical(master, &layers_full, Argon2Config::STANDARD).unwrap();
        let key_partial =
            derive_hierarchical(master, &layers_partial, Argon2Config::STANDARD).unwrap();

        assert_ne!(key_full.as_ref(), key_partial.as_ref());
    }

    #[test]
    fn test_output_length() {
        let master = b"test_master_secret";
        let layers = vec!["layer1".to_string()];

        let key = derive_hierarchical(master, &layers, Argon2Config::PARANOID).unwrap();
        assert_eq!(key.len(), OUTPUT_LEN);
    }
}
