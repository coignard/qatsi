use crate::wordlist::{get_wordlist, wordlist_size};
use anyhow::Result;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use zeroize::Zeroizing;

const ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~";

pub fn generate_mnemonic(key: &[u8; 32], word_count: usize) -> Result<Zeroizing<String>> {
    let wordlist = get_wordlist();
    let wordlist_len = wordlist_size();

    let mut cipher = ChaCha20::new(key.into(), &[0u8; 12].into());
    let mut words = Vec::with_capacity(word_count);

    let max_multiple = 65536 / wordlist_len as u32;
    let rejection_threshold = (max_multiple * wordlist_len as u32) as u16;

    let mut buffer = Zeroizing::new(vec![0u8; 512]);
    cipher.apply_keystream(&mut buffer);
    let mut pos = 0;

    while words.len() < word_count {
        if pos + 1 >= buffer.len() {
            cipher.apply_keystream(&mut buffer);
            pos = 0;
        }

        let random_u16 = u16::from_le_bytes([buffer[pos], buffer[pos + 1]]);
        pos += 2;

        if random_u16 < rejection_threshold {
            let index = (random_u16 % wordlist_len) as usize;
            words.push(wordlist[index]);
        }
    }

    Ok(Zeroizing::new(words.join("-")))
}

pub fn generate_password(key: &[u8; 32], password_length: usize) -> Result<Zeroizing<String>> {
    let mut cipher = ChaCha20::new(key.into(), &[0u8; 12].into());

    let mut password_bytes = Zeroizing::new(Vec::with_capacity(password_length));

    let alphabet_size = ALPHABET.len();
    let rejection_threshold = 256 - (256 % alphabet_size);

    let mut buffer = Zeroizing::new(vec![0u8; 1024]);
    cipher.apply_keystream(&mut buffer);
    let mut pos = 0;

    while password_bytes.len() < password_length {
        if pos >= buffer.len() {
            cipher.apply_keystream(&mut buffer);
            pos = 0;
        }

        let random_byte = buffer[pos];
        pos += 1;

        if (random_byte as usize) < rejection_threshold {
            let index = (random_byte as usize) % alphabet_size;
            password_bytes.push(ALPHABET[index]);
        }
    }

    let result = String::from_utf8(password_bytes.to_vec())?;

    Ok(Zeroizing::new(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_normalization::UnicodeNormalization;

    fn to_zeroizing_vec(v: Vec<String>) -> Vec<Zeroizing<String>> {
        v.into_iter().map(Zeroizing::new).collect()
    }

    fn normalize_string(s: &str) -> String {
        s.trim().nfc().collect()
    }

    #[test]
    fn test_alphabet_size() {
        let size = ALPHABET.len();
        println!("Alphabet: {}", std::str::from_utf8(ALPHABET).unwrap());
        println!("Alphabet size: {}", size);
        assert_eq!(
            size, 90,
            "Alphabet should have 90 characters, found {}",
            size
        );

        use std::collections::HashSet;
        let unique: HashSet<_> = ALPHABET.iter().collect();
        assert_eq!(unique.len(), size, "Alphabet contains duplicates");
    }

    #[test]
    fn test_mnemonic_deterministic() {
        let key = [42u8; 32];
        let mnemonic1 = generate_mnemonic(&key, 24).unwrap();
        let mnemonic2 = generate_mnemonic(&key, 24).unwrap();
        assert_eq!(*mnemonic1, *mnemonic2);
    }

    #[test]
    fn test_mnemonic_word_count() {
        let key = [42u8; 32];
        let mnemonic = generate_mnemonic(&key, 8).unwrap();
        let word_count = mnemonic.split('-').count();
        assert_eq!(word_count, 8);
    }

    #[test]
    fn test_password_deterministic() {
        let key = [42u8; 32];
        let password1 = generate_password(&key, 20).unwrap();
        let password2 = generate_password(&key, 20).unwrap();
        assert_eq!(*password1, *password2);
    }

    #[test]
    fn test_password_length() {
        let key = [42u8; 32];
        let password = generate_password(&key, 20).unwrap();
        assert_eq!(password.len(), 20);
    }

    #[test]
    fn test_password_charset() {
        let key = [42u8; 32];
        let password = generate_password(&key, 48).unwrap();

        for ch in password.bytes() {
            assert!(
                ALPHABET.contains(&ch),
                "Password contains invalid character: \"{}\" (byte {})",
                ch as char,
                ch
            );
        }
    }

    #[test]
    fn test_rejection_threshold() {
        let alphabet_size = ALPHABET.len();
        let threshold = 256 - (256 % alphabet_size);

        println!("Alphabet size: {}", alphabet_size);
        println!("Rejection threshold: {}", threshold);
        println!("Expected: {}", 256 - (256 % 90));
        assert_eq!(threshold, 180);

        for byte in 0u8..=255 {
            if (byte as usize) < threshold {
                let index = (byte as usize) % alphabet_size;
                assert!(
                    index < alphabet_size,
                    "Byte {} maps to invalid index {} (alphabet size: {})",
                    byte,
                    index,
                    alphabet_size
                );
            }
        }
    }

    #[test]
    fn test_regression_mnemonic_standard() {
        let master = b"life";
        let layers = to_zeroizing_vec(vec![
            "out".to_string(),
            "of".to_string(),
            "balance".to_string(),
        ]);

        let key =
            crate::kdf::derive_hierarchical(master, &layers, crate::kdf::Argon2Config::STANDARD)
                .unwrap();

        let mnemonic = generate_mnemonic(&key, 8).unwrap();

        assert_eq!(
            *mnemonic,
            "eagle-huskiness-septum-defection-splatter-version-important-stumble"
        );
    }

    #[test]
    fn test_regression_mnemonic_paranoid() {
        let master = b"life";
        let layers = to_zeroizing_vec(vec![
            "out".to_string(),
            "of".to_string(),
            "balance".to_string(),
        ]);

        let key =
            crate::kdf::derive_hierarchical(master, &layers, crate::kdf::Argon2Config::PARANOID)
                .unwrap();

        let mnemonic = generate_mnemonic(&key, 24).unwrap();

        assert_eq!(
            *mnemonic,
            "vigorous-purebred-exclusion-deface-champion-anatomist-jubilance-snowcap-palace-bankbook-basis-overcast-stunner-augmented-viability-ascension-polygon-spinning-trolling-arson-sagging-line-fraction-rely"
        );
    }

    #[test]
    fn test_regression_password_standard() {
        let master = b"life";
        let layers = to_zeroizing_vec(vec![
            "out".to_string(),
            "of".to_string(),
            "balance".to_string(),
        ]);

        let key =
            crate::kdf::derive_hierarchical(master, &layers, crate::kdf::Argon2Config::STANDARD)
                .unwrap();

        let password = generate_password(&key, 20).unwrap();

        assert_eq!(*password, "6n=rX.k:Qs+)6e5oa-Z:");
    }

    #[test]
    fn test_regression_password_paranoid() {
        let master = b"life";
        let layers = to_zeroizing_vec(vec![
            "out".to_string(),
            "of".to_string(),
            "balance".to_string(),
        ]);

        let key =
            crate::kdf::derive_hierarchical(master, &layers, crate::kdf::Argon2Config::PARANOID)
                .unwrap();

        let password = generate_password(&key, 48).unwrap();

        assert_eq!(
            *password,
            "kex9)5&&$>,N<4}@mDawmgyn<hY_5e@WsvKQsUD*ut9EN^&D"
        );
    }

    #[test]
    fn test_normalization_produces_same_output() {
        let master = b"test";

        let nfc_layers = to_zeroizing_vec(vec![normalize_string("café")]);

        let nfd_layers = to_zeroizing_vec(vec![normalize_string("cafe\u{0301}")]);

        let key_nfc = crate::kdf::derive_hierarchical(
            master,
            &nfc_layers,
            crate::kdf::Argon2Config::STANDARD,
        )
        .unwrap();
        let key_nfd = crate::kdf::derive_hierarchical(
            master,
            &nfd_layers,
            crate::kdf::Argon2Config::STANDARD,
        )
        .unwrap();

        assert_eq!(key_nfc.as_ref(), key_nfd.as_ref());

        let mnemonic_nfc = generate_mnemonic(&key_nfc, 8).unwrap();
        let mnemonic_nfd = generate_mnemonic(&key_nfd, 8).unwrap();
        assert_eq!(*mnemonic_nfc, *mnemonic_nfd);

        let password_nfc = generate_password(&key_nfc, 20).unwrap();
        let password_nfd = generate_password(&key_nfd, 20).unwrap();
        assert_eq!(*password_nfc, *password_nfd);
    }

    #[test]
    fn test_whitespace_trim_produces_same_output() {
        let master = b"test";

        let trimmed_layers = to_zeroizing_vec(vec![normalize_string("password")]);

        let untrimmed_layers = to_zeroizing_vec(vec![normalize_string("  password  ")]);

        let key_trimmed = crate::kdf::derive_hierarchical(
            master,
            &trimmed_layers,
            crate::kdf::Argon2Config::STANDARD,
        )
        .unwrap();
        let key_untrimmed = crate::kdf::derive_hierarchical(
            master,
            &untrimmed_layers,
            crate::kdf::Argon2Config::STANDARD,
        )
        .unwrap();

        assert_eq!(key_trimmed.as_ref(), key_untrimmed.as_ref());

        let mnemonic_trimmed = generate_mnemonic(&key_trimmed, 8).unwrap();
        let mnemonic_untrimmed = generate_mnemonic(&key_untrimmed, 8).unwrap();
        assert_eq!(*mnemonic_trimmed, *mnemonic_untrimmed);

        let password_trimmed = generate_password(&key_trimmed, 20).unwrap();
        let password_untrimmed = generate_password(&key_untrimmed, 20).unwrap();
        assert_eq!(*password_trimmed, *password_untrimmed);
    }

    #[test]
    fn test_combined_normalization_and_trim() {
        let master = b"test";

        let clean_layers = to_zeroizing_vec(vec![normalize_string("café")]);

        let messy_layers = to_zeroizing_vec(vec![normalize_string("  cafe\u{0301}\t\n")]);

        let key_clean = crate::kdf::derive_hierarchical(
            master,
            &clean_layers,
            crate::kdf::Argon2Config::STANDARD,
        )
        .unwrap();
        let key_messy = crate::kdf::derive_hierarchical(
            master,
            &messy_layers,
            crate::kdf::Argon2Config::STANDARD,
        )
        .unwrap();

        assert_eq!(key_clean.as_ref(), key_messy.as_ref());

        let mnemonic_clean = generate_mnemonic(&key_clean, 12).unwrap();
        let mnemonic_messy = generate_mnemonic(&key_messy, 12).unwrap();
        assert_eq!(*mnemonic_clean, *mnemonic_messy);

        let password_clean = generate_password(&key_clean, 32).unwrap();
        let password_messy = generate_password(&key_messy, 32).unwrap();
        assert_eq!(*password_clean, *password_messy);
    }

    #[test]
    fn test_unicode_multiple_normalizations() {
        let master = b"test";

        let test_cases = vec![
            ("René", "Rene\u{0301}"),
            ("Wörlitz", "Wo\u{0308}rlitz"),
            ("Gräfenhainichen", "Gra\u{0308}fenhainichen"),
        ];

        for (nfc, nfd) in test_cases {
            let layers_nfc = to_zeroizing_vec(vec![normalize_string(nfc)]);
            let layers_nfd = to_zeroizing_vec(vec![normalize_string(nfd)]);

            let key_nfc = crate::kdf::derive_hierarchical(
                master,
                &layers_nfc,
                crate::kdf::Argon2Config::STANDARD,
            )
            .unwrap();
            let key_nfd = crate::kdf::derive_hierarchical(
                master,
                &layers_nfd,
                crate::kdf::Argon2Config::STANDARD,
            )
            .unwrap();

            assert_eq!(
                key_nfc.as_ref(),
                key_nfd.as_ref(),
                "Keys should match for {} and its NFD form",
                nfc
            );

            let mnemonic_nfc = generate_mnemonic(&key_nfc, 6).unwrap();
            let mnemonic_nfd = generate_mnemonic(&key_nfd, 6).unwrap();
            assert_eq!(*mnemonic_nfc, *mnemonic_nfd);
        }
    }
}
