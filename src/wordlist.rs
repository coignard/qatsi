// This file is part of Qatsi.
//
// Copyright (c) 2025  René Coignard <contact@renecoignard.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use std::sync::OnceLock;

const WORDLIST_DATA: &str = include_str!("../assets/eff_large_wordlist.txt");

#[cfg(test)]
const EXPECTED_SHA256: &str = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";

static WORDLIST: OnceLock<Vec<&'static str>> = OnceLock::new();

pub fn get_wordlist() -> &'static [&'static str] {
    WORDLIST.get_or_init(|| {
        let words: Vec<&'static str> = WORDLIST_DATA
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| {
                line.split_once('\t')
                    .or_else(|| line.split_once(' '))
                    .map(|(_, word)| word.trim())
            })
            .collect();

        assert_eq!(
            words.len(),
            7776,
            "Wordlist must contain exactly 7776 words"
        );
        words
    })
}

pub const fn wordlist_size() -> u16 {
    7776
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_wordlist_loaded() {
        assert_eq!(get_wordlist().len(), 7776);
    }

    #[test]
    fn test_wordlist_no_duplicates() {
        use std::collections::HashSet;
        let words = get_wordlist();
        let unique: HashSet<_> = words.iter().collect();
        assert_eq!(unique.len(), words.len(), "Wordlist contains duplicates");
    }

    #[test]
    fn test_wordlist_no_empty() {
        let words = get_wordlist();
        assert!(
            words.iter().all(|w| !w.is_empty()),
            "Wordlist contains empty words"
        );
    }

    #[test]
    fn test_wordlist_integrity() {
        let words = get_wordlist();

        assert_eq!(words[0], "abacus", "First word should be \"abacus\"");

        assert_eq!(words[7775], "zoom", "Last word should be \"zoom\"");

        assert_eq!(words[3695], "life", "Word at line 3696 should be \"life\"");

        /* out of */

        assert_eq!(
            words[469], "balance",
            "Word at line 470 should be \"balance\""
        );

        for (i, word) in words.iter().enumerate() {
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "Word at index {} (\"{}\") contains invalid characters",
                i,
                word
            );
            assert!(
                word.len() >= 3 && word.len() <= 9,
                "Word at index {} (\"{}\") has invalid length {}",
                i,
                word,
                word.len()
            )
        }
    }

    #[test]
    fn test_wordlist_sha256() {
        let mut hasher = Sha256::new();
        hasher.update(WORDLIST_DATA.as_bytes());
        let result = format!("{:x}", hasher.finalize());

        assert_eq!(
            result, EXPECTED_SHA256,
            "Wordlist SHA-256 mismatch; file may be corrupted"
        );
    }

    #[test]
    fn test_wordlist_format() {
        let lines: Vec<&str> = WORDLIST_DATA.lines().collect();
        assert_eq!(lines.len(), 7776, "Wordlist should have 7776 lines");

        for (i, line) in lines.iter().enumerate() {
            assert!(
                line.contains('\t') || line.contains(' '),
                "Line {} does not contain separator",
                i + 1
            );
        }
    }
}
