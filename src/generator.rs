use crate::wordlist::{get_wordlist, wordlist_size};
use anyhow::Result;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

const ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~";

pub fn generate_mnemonic(key: &[u8; 32], word_count: usize) -> Result<String> {
    let wordlist = get_wordlist();
    let wordlist_len = wordlist_size();

    let mut cipher = ChaCha20::new(key.into(), &[0u8; 12].into());
    let mut words = Vec::with_capacity(word_count);

    let max_multiple = 65536 / wordlist_len as u32;
    let rejection_threshold = (max_multiple * wordlist_len as u32) as u16;

    let mut buffer = vec![0u8; 2048];
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

    Ok(words.join("-"))
}

pub fn generate_password(key: &[u8; 32], password_length: usize) -> Result<String> {
    let mut cipher = ChaCha20::new(key.into(), &[0u8; 12].into());
    let mut password = Vec::with_capacity(password_length);

    let alphabet_size = ALPHABET.len();
    let rejection_threshold = 256 - (256 % alphabet_size);

    let mut buffer = vec![0u8; 1024];
    cipher.apply_keystream(&mut buffer);
    let mut pos = 0;

    while password.len() < password_length {
        if pos >= buffer.len() {
            cipher.apply_keystream(&mut buffer);
            pos = 0;
        }

        let random_byte = buffer[pos];
        pos += 1;

        if (random_byte as usize) < rejection_threshold {
            let index = (random_byte as usize) % alphabet_size;
            password.push(ALPHABET[index]);
        }
    }

    Ok(String::from_utf8(password)?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(mnemonic1, mnemonic2);
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
        assert_eq!(password1, password2);
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
                "Password contains invalid character: '{}' (byte {})",
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
}
