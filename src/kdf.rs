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
const MIN_SALT_LEN: usize = 16;

pub fn derive_hierarchical(
    master_secret: &[u8],
    layers: &[Zeroizing<String>],
    config: Argon2Config,
) -> Result<Zeroizing<[u8; OUTPUT_LEN]>> {
    if layers.is_empty() {
        anyhow::bail!("Layers array cannot be empty");
    }

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
    let salt: Zeroizing<Vec<u8>> = if salt_input.len() >= MIN_SALT_LEN {
        Zeroizing::new(salt_input.to_vec())
    } else {
        let mut hasher = Blake2b512::new();
        hasher.update(salt_input);
        Zeroizing::new(hasher.finalize().to_vec())
    };

    argon2
        .hash_password_into(password, &salt, output)
        .map_err(|e| anyhow::anyhow!("Argon2 derivation failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_zeroizing_vec(v: Vec<String>) -> Vec<Zeroizing<String>> {
        v.into_iter().map(Zeroizing::new).collect()
    }

    #[test]
    fn test_empty_layers() {
        let master = b"test_master_secret";
        let layers: Vec<Zeroizing<String>> = vec![];

        let result = derive_hierarchical(master, &layers, Argon2Config::STANDARD);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Layers array cannot be empty"));
    }

    #[test]
    fn test_deterministic_derivation() {
        let master = b"test_master_secret";
        let layers = to_zeroizing_vec(vec!["layer1".to_string(), "layer2".to_string()]);

        let key1 = derive_hierarchical(master, &layers, Argon2Config::STANDARD).unwrap();
        let key2 = derive_hierarchical(master, &layers, Argon2Config::STANDARD).unwrap();

        assert_eq!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_different_configs_different_keys() {
        let master = b"test_master_secret";
        let layers = to_zeroizing_vec(vec!["layer1".to_string()]);

        let key_standard = derive_hierarchical(master, &layers, Argon2Config::STANDARD).unwrap();
        let key_paranoid = derive_hierarchical(master, &layers, Argon2Config::PARANOID).unwrap();

        assert_ne!(key_standard.as_ref(), key_paranoid.as_ref());
    }

    #[test]
    fn test_different_layers_different_keys() {
        let master = b"test_master_secret";
        let layers1 = to_zeroizing_vec(vec!["layer1".to_string()]);
        let layers2 = to_zeroizing_vec(vec!["layer2".to_string()]);

        let key1 = derive_hierarchical(master, &layers1, Argon2Config::STANDARD).unwrap();
        let key2 = derive_hierarchical(master, &layers2, Argon2Config::STANDARD).unwrap();

        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_hierarchical_chaining() {
        let master = b"test_master_secret";
        let layers_full = to_zeroizing_vec(vec!["layer1".to_string(), "layer2".to_string()]);
        let layers_partial = to_zeroizing_vec(vec!["layer1".to_string()]);

        let key_full = derive_hierarchical(master, &layers_full, Argon2Config::STANDARD).unwrap();
        let key_partial =
            derive_hierarchical(master, &layers_partial, Argon2Config::STANDARD).unwrap();

        assert_ne!(key_full.as_ref(), key_partial.as_ref());
    }

    #[test]
    fn test_output_length() {
        let master = b"test_master_secret";
        let layers = to_zeroizing_vec(vec!["layer1".to_string()]);

        let key = derive_hierarchical(master, &layers, Argon2Config::PARANOID).unwrap();
        assert_eq!(key.len(), OUTPUT_LEN);
    }

    #[test]
    fn test_unicode_layers() {
        let master = b"test_master_secret";

        let layers_cyrillic = to_zeroizing_vec(vec!["жизнь".to_string()]);
        let key_cyrillic =
            derive_hierarchical(master, &layers_cyrillic, Argon2Config::STANDARD).unwrap();

        let layers_korean = to_zeroizing_vec(vec!["생활".to_string()]);
        let key_korean =
            derive_hierarchical(master, &layers_korean, Argon2Config::STANDARD).unwrap();

        let layers_emoji = to_zeroizing_vec(vec!["🔐🔑".to_string()]);
        let key_emoji = derive_hierarchical(master, &layers_emoji, Argon2Config::STANDARD).unwrap();

        assert_ne!(key_cyrillic.as_ref(), key_korean.as_ref());
        assert_ne!(key_cyrillic.as_ref(), key_emoji.as_ref());
        assert_ne!(key_korean.as_ref(), key_emoji.as_ref());

        let key_cyrillic2 =
            derive_hierarchical(master, &layers_cyrillic, Argon2Config::STANDARD).unwrap();
        assert_eq!(key_cyrillic.as_ref(), key_cyrillic2.as_ref());
    }

    #[test]
    fn test_unicode_normalization_sensitivity() {
        let master = b"test_master_secret";

        let nfc = to_zeroizing_vec(vec!["café".to_string()]);
        let nfd = to_zeroizing_vec(vec!["cafe\u{0301}".to_string()]);

        let key_nfc = derive_hierarchical(master, &nfc, Argon2Config::STANDARD).unwrap();
        let key_nfd = derive_hierarchical(master, &nfd, Argon2Config::STANDARD).unwrap();

        println!("NFC bytes: {:?}", nfc[0].as_bytes());
        println!("NFD bytes: {:?}", nfd[0].as_bytes());
        println!("Keys equal: {}", key_nfc.as_ref() == key_nfd.as_ref());
    }

    #[test]
    fn test_unicode_multi_byte_chars() {
        let master = b"test_master_secret";

        let ascii = to_zeroizing_vec(vec!["a".to_string()]);
        let cyrillic = to_zeroizing_vec(vec!["б".to_string()]);
        let chinese = to_zeroizing_vec(vec!["中".to_string()]);
        let emoji = to_zeroizing_vec(vec!["🔐".to_string()]);

        assert_eq!(ascii[0].len(), 1);
        assert_eq!(cyrillic[0].len(), 2);
        assert_eq!(chinese[0].len(), 3);
        assert_eq!(emoji[0].len(), 4);

        let key_ascii = derive_hierarchical(master, &ascii, Argon2Config::STANDARD).unwrap();
        let key_cyrillic = derive_hierarchical(master, &cyrillic, Argon2Config::STANDARD).unwrap();
        let key_chinese = derive_hierarchical(master, &chinese, Argon2Config::STANDARD).unwrap();
        let key_emoji = derive_hierarchical(master, &emoji, Argon2Config::STANDARD).unwrap();

        assert_ne!(key_ascii.as_ref(), key_cyrillic.as_ref());
        assert_ne!(key_ascii.as_ref(), key_chinese.as_ref());
        assert_ne!(key_ascii.as_ref(), key_emoji.as_ref());
    }

    #[test]
    fn test_unicode_mixed_layers() {
        let master = "мастер🔑".as_bytes();
        let layers = to_zeroizing_vec(vec![
            "жизнь".to_string(),
            "生活".to_string(),
            "생활".to_string(),
            "🌍🌎🌏".to_string(),
        ]);

        let key = derive_hierarchical(master, &layers, Argon2Config::STANDARD).unwrap();

        assert_eq!(key.len(), 32);

        let key2 = derive_hierarchical(master, &layers, Argon2Config::STANDARD).unwrap();
        assert_eq!(key.as_ref(), key2.as_ref());
    }

    #[test]
    fn test_unicode_whitespace() {
        let master = b"test";

        let space = to_zeroizing_vec(vec!["hello world".to_string()]);
        let nbsp = to_zeroizing_vec(vec!["hello\u{00A0}world".to_string()]);
        let zwsp = to_zeroizing_vec(vec!["hello\u{200B}world".to_string()]);

        let key_space = derive_hierarchical(master, &space, Argon2Config::STANDARD).unwrap();
        let key_nbsp = derive_hierarchical(master, &nbsp, Argon2Config::STANDARD).unwrap();
        let key_zwsp = derive_hierarchical(master, &zwsp, Argon2Config::STANDARD).unwrap();

        assert_ne!(key_space.as_ref(), key_nbsp.as_ref());
        assert_ne!(key_space.as_ref(), key_zwsp.as_ref());
    }

    #[test]
    fn test_entropy_calculation_bytes() {
        let ascii = "hello";
        let cyrillic = "привет";
        let emoji = "🔐🔑";

        assert_eq!(ascii.len(), 5);
        assert_eq!(ascii.chars().count(), 5);

        assert_eq!(cyrillic.len(), 12);
        assert_eq!(cyrillic.chars().count(), 6);

        assert_eq!(emoji.len(), 8);
        assert_eq!(emoji.chars().count(), 2);

        let entropy_ascii = ascii.len() as f64 * 8.0;
        let entropy_cyrillic = cyrillic.len() as f64 * 8.0;
        let entropy_emoji = emoji.len() as f64 * 8.0;

        assert_eq!(entropy_ascii, 40.0);
        assert_eq!(entropy_cyrillic, 96.0);
        assert_eq!(entropy_emoji, 64.0);
    }
}
