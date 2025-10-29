use anyhow::{Context, Result};
use console::{Style, Term};
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::read_password;
use std::io::{self, Write};
use std::time::{Duration, Instant};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const MIN_SAFE_ENTROPY: f64 = 100.0;
pub const PARANOID_ENTROPY: f64 = 300.0;

pub const MIN_MASTER_BYTES: usize = 16;
pub const MIN_LAYER_BYTES: usize = 4;
pub const MIN_LAYERS_COUNT: usize = 2;

pub const MAX_MASTER_BYTES: usize = 1024 * 1024;
pub const MAX_LAYER_BYTES: usize = 1024 * 1024;
pub const MAX_LAYERS_COUNT: usize = 100;

pub const MIN_KDF_MEMORY_MIB_STANDARD: u32 = 32;
pub const MIN_KDF_ITERATIONS_STANDARD: u32 = 8;
pub const MIN_KDF_PARALLELISM_STANDARD: u32 = 4;

pub const MIN_KDF_MEMORY_MIB_PARANOID: u32 = 64;
pub const MIN_KDF_ITERATIONS_PARANOID: u32 = 16;
pub const MIN_KDF_PARALLELISM_PARANOID: u32 = 4;

pub const MIN_SAFE_WORD_COUNT: usize = 8;
pub const MIN_SAFE_PASSWORD_LENGTH: usize = 20;

pub struct InputInfo {
    pub master_byte_length: usize,
    pub master_char_count: usize,
    pub layers: Vec<LayerInfo>,
}

pub struct LayerInfo {
    pub index: usize,
    pub byte_length: usize,
    pub char_count: usize,
}

pub struct OutputConfig {
    pub word_count: usize,
    pub password_length: usize,
    pub wordlist_size: usize,
    pub charset_size: usize,
    pub is_mnemonic: bool,
}

pub struct DisplayOptions {
    pub unicode_support: bool,
    pub color_support: bool,
    pub quiet: bool,
}

pub fn detect_unicode_support() -> bool {
    supports_unicode::on(supports_unicode::Stream::Stdout)
}

pub fn detect_color_support() -> bool {
    supports_color::on(supports_color::Stream::Stdout).is_some()
}

pub fn get_status_symbols(unicode_support: bool) -> (&'static str, &'static str) {
    if unicode_support {
        ("✓", "!")
    } else {
        ("+", "!")
    }
}

fn validate_control_characters(s: &str, input_name: &str) -> Result<String> {
    let control_chars: Vec<(usize, char)> = s
        .chars()
        .enumerate()
        .filter(|(_, c)| c.is_control())
        .collect();

    if !control_chars.is_empty() {
        let term = Term::stderr();

        let warning_msg = format!(
            "WARNING: {} contains {} control character(s) at position(s): {}",
            input_name,
            control_chars.len(),
            control_chars
                .iter()
                .map(|(pos, _)| pos.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        term.write_line(&warning_msg)?;
        term.write_str("Continue anyway? [y/N]: ")?;
        term.flush()?;

        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        let response = response.trim().to_lowercase();

        term.clear_last_lines(2)?;

        if response != "y" && response != "yes" {
            eprintln!("Aborted.");
            std::process::exit(1);
        }
    }

    Ok(s.to_string())
}

fn normalize_and_validate(s: &str, input_name: &str) -> Result<String> {
    let trimmed = s.trim();
    let normalized: String = trimmed.nfc().collect();
    validate_control_characters(&normalized, input_name)
}

pub fn prompt_master_secret() -> Result<(Zeroizing<Vec<u8>>, usize, usize)> {
    print!("In [0]: ");
    io::stdout().flush()?;

    let password = read_password().context("Failed to fetch master secret")?;

    if password.is_empty() {
        anyhow::bail!("Master secret cannot be empty");
    }

    let normalized = normalize_and_validate(&password, "Master secret")?;

    let byte_length = normalized.len();
    if byte_length > MAX_MASTER_BYTES {
        anyhow::bail!(
            "Master secret too long ({} bytes, maximum is {})",
            byte_length,
            MAX_MASTER_BYTES
        );
    }

    let char_count = normalized.chars().count();
    Ok((
        Zeroizing::new(normalized.into_bytes()),
        byte_length,
        char_count,
    ))
}

pub fn prompt_layers() -> Result<(Vec<Zeroizing<String>>, Vec<LayerInfo>)> {
    let mut layers = Vec::new();
    let mut layer_infos = Vec::new();
    let mut index = 1;

    loop {
        if index > MAX_LAYERS_COUNT {
            anyhow::bail!("Too many layers ({} maximum allowed)", MAX_LAYERS_COUNT);
        }

        print!("In [{}]: ", index);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let trimmed = input.trim();
        if trimmed.is_empty() {
            break;
        }

        let normalized = normalize_and_validate(trimmed, &format!("Layer {}", index))?;

        let byte_length = normalized.len();
        if byte_length > MAX_LAYER_BYTES {
            anyhow::bail!(
                "Layer {} too long ({} bytes, maximum is {})",
                index,
                byte_length,
                MAX_LAYER_BYTES
            );
        }

        let char_count = normalized.chars().count();
        layers.push(Zeroizing::new(normalized));
        layer_infos.push(LayerInfo {
            index,
            byte_length,
            char_count,
        });
        index += 1;
    }

    if layers.is_empty() {
        anyhow::bail!("At least one layer is required");
    }

    Ok((layers, layer_infos))
}

pub fn show_progress<F, T>(unicode_support: bool, f: F) -> Result<(T, Duration)>
where
    F: FnOnce() -> Result<T>,
{
    println!();

    let term = Term::stdout();
    term.hide_cursor().ok();

    let pb = ProgressBar::new_spinner();

    if unicode_support {
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner())
                .tick_strings(&[
                    "⠁", "⠂", "⠄", "⡀", "⡈", "⡐", "⡠", "⣀", "⣁", "⣂", "⣄", "⣌", "⣔", "⣤", "⣥", "⣦",
                    "⣮", "⣶", "⣷", "⣿", "⡿", "⠿", "⢟", "⠟", "⡛", "⠛", "⠫", "⢋", "⠋", "⠍", "⡉", "⠉",
                    "⠑", "⠡", "⢁", "⠁",
                ]),
        );
    } else {
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner())
                .tick_chars("-\\|/-"),
        );
    }

    pb.set_message("Deriving key...");
    pb.enable_steady_tick(Duration::from_millis(80));

    let start = Instant::now();
    let result = f();
    let elapsed = start.elapsed();

    pb.finish_and_clear();
    term.show_cursor().ok();

    result.map(|r| (r, elapsed))
}

pub fn display_output(
    output: &Zeroizing<String>,
    input_info: &InputInfo,
    config: &OutputConfig,
    kdf_config: &crate::kdf::Argon2Config,
    elapsed: Duration,
    options: &DisplayOptions,
) {
    if options.quiet {
        println!("Out[0]:\n{}", &**output);
    } else {
        println!("Out[0]:\n{}\n", &**output);

        let entropy = if config.is_mnemonic {
            config.word_count as f64 * (config.wordlist_size as f64).log2()
        } else {
            config.password_length as f64 * (config.charset_size as f64).log2()
        };

        display_settings(input_info, config, kdf_config, options);
        display_stats(entropy, output.len(), config, elapsed, options);
    }
}

fn display_settings(
    input_info: &InputInfo,
    config: &OutputConfig,
    kdf_config: &crate::kdf::Argon2Config,
    options: &DisplayOptions,
) {
    let (check_ok, check_warn) = get_status_symbols(options.unicode_support);

    let memory_mib = kdf_config.memory_mib();

    let (min_memory, min_iterations, min_parallelism) = if memory_mib >= MIN_KDF_MEMORY_MIB_PARANOID
    {
        (
            MIN_KDF_MEMORY_MIB_PARANOID,
            MIN_KDF_ITERATIONS_PARANOID,
            MIN_KDF_PARALLELISM_PARANOID,
        )
    } else {
        (
            MIN_KDF_MEMORY_MIB_STANDARD,
            MIN_KDF_ITERATIONS_STANDARD,
            MIN_KDF_PARALLELISM_STANDARD,
        )
    };

    let kdf_secure = memory_mib >= min_memory
        && kdf_config.iterations >= min_iterations
        && kdf_config.parallelism >= min_parallelism;
    let master_bytes_secure = input_info.master_byte_length >= MIN_MASTER_BYTES;
    let layers_secure = input_info.layers.len() >= MIN_LAYERS_COUNT;

    let kdf_style = if options.color_support {
        if kdf_secure {
            Style::new().green()
        } else {
            Style::new().yellow()
        }
    } else {
        Style::new()
    };

    let master_bytes_style = if options.color_support {
        if master_bytes_secure {
            Style::new().green()
        } else {
            Style::new().yellow()
        }
    } else {
        Style::new()
    };

    let layers_style = if options.color_support {
        if layers_secure {
            Style::new().green()
        } else {
            Style::new().yellow()
        }
    } else {
        Style::new()
    };

    let kdf_status = if kdf_secure { check_ok } else { check_warn };
    let master_status = if master_bytes_secure {
        check_ok
    } else {
        check_warn
    };
    let layers_status = if layers_secure { check_ok } else { check_warn };

    println!("Settings:");

    println!(
        "  ├─ KDF        {} Argon2id (m={} MiB, t={}, p={})",
        kdf_style.apply_to(format!("[{}]", kdf_status)),
        kdf_style.apply_to(memory_mib),
        kdf_style.apply_to(kdf_config.iterations),
        kdf_style.apply_to(kdf_config.parallelism)
    );

    println!(
        "  ├─ Master     {} {} {} ({} {})",
        master_bytes_style.apply_to(format!("[{}]", master_status)),
        master_bytes_style.apply_to(input_info.master_byte_length),
        if input_info.master_byte_length == 1 {
            "byte"
        } else {
            "bytes"
        },
        master_bytes_style.apply_to(input_info.master_char_count),
        if input_info.master_char_count == 1 {
            "char"
        } else {
            "chars"
        }
    );

    println!(
        "  ├─ Layers     {} {} {}",
        layers_style.apply_to(format!("[{}]", layers_status)),
        layers_style.apply_to(input_info.layers.len()),
        if input_info.layers.len() == 1 {
            "layer"
        } else {
            "layers"
        }
    );

    for (i, layer) in input_info.layers.iter().enumerate() {
        let is_last = i == input_info.layers.len() - 1;
        let prefix = if is_last {
            "│  └─"
        } else {
            "│  ├─"
        };
        let layer_bytes_secure = layer.byte_length >= MIN_LAYER_BYTES;

        let layer_bytes_style = if options.color_support {
            if layer_bytes_secure {
                Style::new().green()
            } else {
                Style::new().yellow()
            }
        } else {
            Style::new()
        };

        let layer_status = if layer_bytes_secure {
            check_ok
        } else {
            check_warn
        };

        println!(
            "  {} {} In [{}]: {} {} ({} {})",
            prefix,
            layer_bytes_style.apply_to(format!("[{}]", layer_status)),
            layer.index,
            layer_bytes_style.apply_to(layer.byte_length),
            if layer.byte_length == 1 {
                "byte"
            } else {
                "bytes"
            },
            layer_bytes_style.apply_to(layer.char_count),
            if layer.char_count == 1 {
                "char"
            } else {
                "chars"
            }
        );
    }

    println!("  ├─ Keystream  ChaCha20 (256-bit)");
    println!("  ├─ Sampling   Unbiased rejection");

    if config.is_mnemonic {
        println!(
            "  └─ Output     {} {}",
            config.word_count,
            if config.word_count == 1 {
                "word"
            } else {
                "words"
            }
        );
    } else {
        println!(
            "  └─ Output     {} {}",
            config.password_length,
            if config.password_length == 1 {
                "char"
            } else {
                "chars"
            }
        );
    }

    println!();
}

fn display_stats(
    entropy: f64,
    length: usize,
    config: &OutputConfig,
    elapsed: Duration,
    options: &DisplayOptions,
) {
    let (check_ok, check_warn) = get_status_symbols(options.unicode_support);

    let (status_icon, entropy_style, status_text) = if entropy >= PARANOID_ENTROPY {
        (
            check_ok,
            if options.color_support {
                Style::new().green()
            } else {
                Style::new()
            },
            "Paranoid",
        )
    } else if entropy >= MIN_SAFE_ENTROPY {
        (
            check_ok,
            if options.color_support {
                Style::new().green()
            } else {
                Style::new()
            },
            "Strong",
        )
    } else {
        (
            check_warn,
            if options.color_support {
                Style::new().yellow()
            } else {
                Style::new()
            },
            "Weak",
        )
    };

    let length_secure = if config.is_mnemonic {
        config.word_count >= MIN_SAFE_WORD_COUNT
    } else {
        config.password_length >= MIN_SAFE_PASSWORD_LENGTH
    };

    let length_style = if options.color_support {
        if length_secure {
            Style::new().green()
        } else {
            Style::new().yellow()
        }
    } else {
        Style::new()
    };

    let length_status = if length_secure { check_ok } else { check_warn };

    println!("Stats:");

    print!(
        "  ├─ Entropy    {} ",
        entropy_style.apply_to(format!("[{}]", status_icon))
    );
    print!("{}", entropy_style.apply_to(format!("{:.1}", entropy)));
    print!(" bits ({})", entropy_style.apply_to(status_text));
    println!();

    print!(
        "  ├─ Length     {} ",
        length_style.apply_to(format!("[{}]", length_status))
    );
    print!("{}", length_style.apply_to(length));
    print!(" {}", if length == 1 { "char" } else { "chars" });
    println!();

    if config.is_mnemonic {
        print!(
            "  ├─ Words      {} ",
            length_style.apply_to(format!("[{}]", length_status))
        );
        print!("{}", length_style.apply_to(config.word_count));
        print!(
            " {}",
            if config.word_count == 1 {
                "word"
            } else {
                "words"
            }
        );
        println!();
        println!("  ├─ Wordlist   EFF Large ({} words)", config.wordlist_size);
    } else {
        println!("  ├─ Charset    {} chars", config.charset_size);
    }

    println!("  └─ Time       {:.1}s", elapsed.as_secs_f64());

    println!(
        "\n{} Security: {}",
        entropy_style.apply_to(format!("[{}]", status_icon)),
        entropy_style.apply_to(status_text)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_status_symbols_unicode() {
        let (ok, warn) = get_status_symbols(true);
        assert_eq!(ok, "✓");
        assert_eq!(warn, "!");
    }

    #[test]
    fn test_get_status_symbols_ascii() {
        let (ok, warn) = get_status_symbols(false);
        assert_eq!(ok, "+");
        assert_eq!(warn, "!");
    }

    #[test]
    fn test_normalize_nfc() {
        let nfc = "café";
        let nfd = "cafe\u{0301}";

        assert_ne!(nfc.as_bytes(), nfd.as_bytes());

        let normalized_nfc = normalize_and_validate(nfc, "test").unwrap();
        let normalized_nfd = normalize_and_validate(nfd, "test").unwrap();

        assert_eq!(normalized_nfc, normalized_nfd);
        assert_eq!(normalized_nfc.as_bytes(), normalized_nfd.as_bytes());
    }

    #[test]
    fn test_normalize_unicode_variants() {
        let cases = vec![
            ("café", "cafe\u{0301}"),
            ("Å", "A\u{030A}"),
            ("ñ", "n\u{0303}"),
        ];

        for (nfc, nfd) in cases {
            let normalized_nfc = normalize_and_validate(nfc, "test").unwrap();
            let normalized_nfd = normalize_and_validate(nfd, "test").unwrap();
            assert_eq!(normalized_nfc, normalized_nfd);
        }
    }

    #[test]
    fn test_trim_whitespace() {
        let cases = vec![
            ("  password  ", "password"),
            ("\tpassword\t", "password"),
            ("\npassword\n", "password"),
            ("  pass word  ", "pass word"),
            (" café ", "café"),
        ];

        for (input, expected) in cases {
            let normalized = normalize_and_validate(input, "test").unwrap();
            assert_eq!(normalized, expected);
        }
    }

    #[test]
    fn test_trim_and_normalize_combined() {
        let input = "  café  ";
        let nfd_input = "  cafe\u{0301}  ";

        let normalized1 = normalize_and_validate(input, "test").unwrap();
        let normalized2 = normalize_and_validate(nfd_input, "test").unwrap();

        assert_eq!(normalized1, "café");
        assert_eq!(normalized2, "café");
        assert_eq!(normalized1, normalized2);
    }

    #[test]
    fn test_unicode_multibyte_preservation() {
        let inputs = vec![
            "жизнь".to_string(),
            "ცხოვრება".to_string(),
            "生活".to_string(),
            "생활".to_string(),
            "🌍🌎🌏".to_string(),
        ];

        for input in inputs {
            let normalized = normalize_and_validate(&input, "test").unwrap();
            assert!(!normalized.is_empty());
            assert_eq!(normalized.chars().count(), input.chars().count());
        }
    }

    #[test]
    fn test_normalization_idempotent() {
        let input = "café\u{0301}";

        let first = normalize_and_validate(input, "test").unwrap();
        let second = normalize_and_validate(&first, "test").unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn test_empty_after_trim() {
        let inputs = vec!["   ", "\t\t", "\n\n", ""];

        for input in inputs {
            let normalized = normalize_and_validate(input, "test").unwrap();
            assert_eq!(normalized, "");
        }
    }
}
