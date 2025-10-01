use anyhow::{Context, Result};
use console::{Style, Term};
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::read_password;
use std::io::{self, Write};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const MIN_SAFE_ENTROPY: f64 = 100.0;
pub const PARANOID_ENTROPY: f64 = 200.0;
pub const MIN_MASTER_LENGTH: usize = 16;
pub const MIN_LAYER_LENGTH: usize = 4;

pub const MIN_KDF_MEMORY_MIB_STANDARD: u32 = 32;
pub const MIN_KDF_ITERATIONS_STANDARD: u32 = 8;
pub const MIN_KDF_PARALLELISM_STANDARD: u32 = 4;

pub const MIN_KDF_MEMORY_MIB_PARANOID: u32 = 64;
pub const MIN_KDF_ITERATIONS_PARANOID: u32 = 16;
pub const MIN_KDF_PARALLELISM_PARANOID: u32 = 4;

pub struct InputInfo {
    pub master_length: usize,
    pub layers: Vec<LayerInfo>,
}

pub struct LayerInfo {
    pub index: usize,
    pub length: usize,
}

pub struct OutputConfig {
    pub word_count: usize,
    pub password_length: usize,
    pub wordlist_size: usize,
    pub charset_size: usize,
    pub is_mnemonic: bool,
}

pub fn prompt_master_secret() -> Result<(Zeroizing<Vec<u8>>, usize)> {
    print!("In [0]: ");
    io::stdout().flush()?;

    let password = read_password().context("Failed to fetch master secret")?;

    if password.is_empty() {
        anyhow::bail!("Master secret cannot be empty");
    }

    let length = password.len();
    Ok((Zeroizing::new(password.into_bytes()), length))
}

pub fn prompt_layers() -> Result<(Vec<String>, Vec<LayerInfo>)> {
    let mut layers = Vec::new();
    let mut layer_infos = Vec::new();
    let mut index = 1;

    loop {
        print!("In [{}]: ", index);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_string();

        if input.is_empty() {
            break;
        }

        let length = input.len();
        layers.push(input);
        layer_infos.push(LayerInfo { index, length });
        index += 1;
    }

    if layers.is_empty() {
        anyhow::bail!("At least one layer is required");
    }

    Ok((layers, layer_infos))
}

pub fn show_progress<F, T>(f: F) -> Result<(T, Duration)>
where
    F: FnOnce() -> Result<T>,
{
    println!();

    let term = Term::stdout();
    term.hide_cursor().ok();

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
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
    output: &str,
    input_info: &InputInfo,
    config: &OutputConfig,
    kdf_config: &crate::kdf::Argon2Config,
    elapsed: Duration,
) {
    let entropy = if config.is_mnemonic {
        config.word_count as f64 * (config.wordlist_size as f64).log2()
    } else {
        config.password_length as f64 * (config.charset_size as f64).log2()
    };

    println!("Out[0]:\n{}\n", output);

    display_settings(input_info, config, kdf_config);
    display_stats(entropy, output.len(), config, elapsed);
}

fn display_settings(
    input_info: &InputInfo,
    config: &OutputConfig,
    kdf_config: &crate::kdf::Argon2Config,
) {
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
    let master_secure = input_info.master_length >= MIN_MASTER_LENGTH;
    let layers_secure = input_info.layers.len() >= 2;

    let kdf_style = if kdf_secure {
        Style::new().green()
    } else {
        Style::new().yellow()
    };
    let master_style = if master_secure {
        Style::new().green()
    } else {
        Style::new().yellow()
    };
    let layers_style = if layers_secure {
        Style::new().green()
    } else {
        Style::new().yellow()
    };

    let kdf_status = if kdf_secure { "✓" } else { "!" };
    let master_status = if master_secure { "✓" } else { "!" };
    let layers_status = if layers_secure { "✓" } else { "!" };

    println!("Settings:");

    println!(
        "  ├─ KDF        {} Argon2id (m={} MiB, t={}, p={})",
        kdf_style.apply_to(format!("[{}]", kdf_status)),
        kdf_style.apply_to(memory_mib),
        kdf_style.apply_to(kdf_config.iterations),
        kdf_style.apply_to(kdf_config.parallelism)
    );

    println!(
        "  ├─ Master     {} {} character(s)",
        master_style.apply_to(format!("[{}]", master_status)),
        master_style.apply_to(input_info.master_length)
    );

    println!(
        "  ├─ Layers     {} {} layer{}",
        layers_style.apply_to(format!("[{}]", layers_status)),
        layers_style.apply_to(input_info.layers.len()),
        if input_info.layers.len() == 1 {
            ""
        } else {
            "s"
        }
    );

    for (i, layer) in input_info.layers.iter().enumerate() {
        let is_last = i == input_info.layers.len() - 1;
        let prefix = if is_last { "└─" } else { "├─" };
        let layer_secure = layer.length >= MIN_LAYER_LENGTH;
        let layer_style = if layer_secure {
            Style::new().green()
        } else {
            Style::new().yellow()
        };
        let layer_status = if layer_secure { "✓" } else { "!" };

        println!(
            "  │  {} {} In [{}]: {} character(s)",
            prefix,
            layer_style.apply_to(format!("[{}]", layer_status)),
            layer.index,
            layer_style.apply_to(layer.length)
        );
    }

    println!("  ├─ PRNG       ChaCha20 (256-bit)");
    println!("  ├─ Sampling   Unbiased rejection");

    if config.is_mnemonic {
        println!("  └─ Output     {} words", config.word_count);
    } else {
        println!("  └─ Output     {} character(s)", config.password_length);
    }

    println!();
}

fn display_stats(entropy: f64, length: usize, config: &OutputConfig, elapsed: Duration) {
    let (status_icon, entropy_style, status_text) = if entropy >= PARANOID_ENTROPY {
        ("✓", Style::new().green(), "Paranoid")
    } else if entropy >= MIN_SAFE_ENTROPY {
        ("✓", Style::new().green(), "Strong")
    } else {
        ("!", Style::new().yellow(), "Weak")
    };

    let length_secure = if config.is_mnemonic {
        config.word_count >= 8
    } else {
        config.password_length >= 20
    };

    let length_style = if length_secure {
        Style::new().green()
    } else {
        Style::new().yellow()
    };
    let length_status = if length_secure { "✓" } else { "!" };

    println!("Stats:");

    println!(
        "  ├─ Entropy    {} {} bits ({})",
        entropy_style.apply_to(format!("[{}]", status_icon)),
        entropy_style.apply_to(format!("{:.1}", entropy)),
        entropy_style.apply_to(status_text)
    );

    println!(
        "  ├─ Length     {} {} character(s)",
        length_style.apply_to(format!("[{}]", length_status)),
        length_style.apply_to(length)
    );

    if config.is_mnemonic {
        println!(
            "  ├─ Words      {} {}",
            length_style.apply_to(format!("[{}]", length_status)),
            length_style.apply_to(config.word_count)
        );
        println!("  ├─ Wordlist   EFF Large ({} words)", config.wordlist_size);
    } else {
        println!("  ├─ Charset    {} character(s)", config.charset_size);
    }

    println!("  └─ Time       {:.1}s", elapsed.as_secs_f64());

    println!(
        "\n[{}] Security: {}",
        entropy_style.apply_to(status_icon),
        entropy_style.apply_to(status_text)
    );
}
