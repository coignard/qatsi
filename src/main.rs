mod generator;
mod kdf;
mod ui;
mod wordlist;

use anyhow::Result;
use clap::{Parser, ValueEnum};

#[derive(Parser)]
#[command(
    name = "qatsi",
    version,
    author,
    about = "Hierarchical deterministic passphrase generator using Argon2id"
)]
struct Cli {
    #[arg(short, long, value_enum, default_value = "mnemonic")]
    mode: Mode,

    #[arg(short, long, value_enum, default_value = "standard")]
    security: SecurityLevel,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
enum Mode {
    Mnemonic,
    Password,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
enum SecurityLevel {
    Standard,
    Paranoid,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let (master_secret, master_length) = ui::prompt_master_secret()?;
    let (layers, layer_infos) = ui::prompt_layers()?;

    let input_info = ui::InputInfo {
        master_length,
        layers: layer_infos,
    };

    let kdf_config = match cli.security {
        SecurityLevel::Standard => kdf::Argon2Config::STANDARD,
        SecurityLevel::Paranoid => kdf::Argon2Config::PARANOID,
    };

    let output_config = match (cli.mode, cli.security) {
        (Mode::Mnemonic, SecurityLevel::Standard) => ui::OutputConfig {
            word_count: 8,
            password_length: 0,
            wordlist_size: 7776,
            charset_size: 0,
            is_mnemonic: true,
        },
        (Mode::Mnemonic, SecurityLevel::Paranoid) => ui::OutputConfig {
            word_count: 24,
            password_length: 0,
            wordlist_size: 7776,
            charset_size: 0,
            is_mnemonic: true,
        },
        (Mode::Password, SecurityLevel::Standard) => ui::OutputConfig {
            word_count: 0,
            password_length: 20,
            wordlist_size: 0,
            charset_size: 90,
            is_mnemonic: false,
        },
        (Mode::Password, SecurityLevel::Paranoid) => ui::OutputConfig {
            word_count: 0,
            password_length: 48,
            wordlist_size: 0,
            charset_size: 90,
            is_mnemonic: false,
        },
    };

    let ((output, info, out_cfg, kdf_cfg), elapsed) = ui::show_progress(|| {
        let final_key = kdf::derive_hierarchical(&master_secret, &layers, kdf_config)?;

        if output_config.is_mnemonic {
            let mnemonic = generator::generate_mnemonic(&final_key, output_config.word_count)?;
            Ok((mnemonic, input_info, output_config, kdf_config))
        } else {
            let password = generator::generate_password(&final_key, output_config.password_length)?;
            Ok((password, input_info, output_config, kdf_config))
        }
    })?;

    ui::display_output(&output, &info, &out_cfg, &kdf_cfg, elapsed);

    Ok(())
}
