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
    about = "Stateless secret generation via hierarchical memory-hard key derivation using Argon2id",
    help_template = "\
{usage-heading} {usage}

{all-args}{after-help}
"
)]
struct Cli {
    #[arg(
        short,
        long,
        value_enum,
        default_value = "mnemonic",
        help = "Output mode: a mnemonic phrase or a random password"
    )]
    mode: Mode,

    #[arg(
        short,
        long,
        value_enum,
        default_value = "standard",
        help = "Security preset for KDF parameters and output length"
    )]
    security: SecurityLevel,

    #[arg(long, value_name = "COUNT", help = "Override mnemonic word count")]
    words: Option<usize>,

    #[arg(long, value_name = "LENGTH", help = "Override password length")]
    length: Option<usize>,

    #[arg(long, value_name = "MIB", help = "Override KDF memory cost")]
    kdf_memory: Option<u32>,

    #[arg(long, value_name = "COUNT", help = "Override KDF iterations")]
    kdf_iterations: Option<u32>,

    #[arg(long, value_name = "LANES", help = "Override KDF parallelism")]
    kdf_parallelism: Option<u32>,

    #[arg(long, help = "Disable Unicode output")]
    no_unicode: bool,

    #[arg(long, help = "Disable colored output")]
    no_color: bool,

    #[arg(short, long, help = "Suppress settings and statistics output")]
    quiet: bool,
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

    let color_support = if cli.no_color {
        false
    } else {
        ui::detect_color_support()
    };

    let unicode_support = if cli.no_unicode {
        false
    } else {
        ui::detect_unicode_support()
    };

    let (master_secret, master_byte_length, master_char_count) = ui::prompt_master_secret()?;

    let (layers, layer_infos) = ui::prompt_layers()?;

    let input_info = ui::InputInfo {
        master_byte_length,
        master_char_count,
        layers: layer_infos,
    };

    let mut kdf_config = match cli.security {
        SecurityLevel::Standard => kdf::Argon2Config::STANDARD,
        SecurityLevel::Paranoid => kdf::Argon2Config::PARANOID,
    };

    if let Some(mem) = cli.kdf_memory {
        kdf_config.memory_kib = mem * 1024;
    }
    if let Some(iter) = cli.kdf_iterations {
        kdf_config.iterations = iter;
    }
    if let Some(par) = cli.kdf_parallelism {
        kdf_config.parallelism = par;
    }

    let (default_words, default_length) = match cli.security {
        SecurityLevel::Standard => (8, 20),
        SecurityLevel::Paranoid => (24, 48),
    };

    let output_config = match cli.mode {
        Mode::Mnemonic => ui::OutputConfig {
            word_count: cli.words.unwrap_or(default_words),
            password_length: 0,
            wordlist_size: 7776,
            charset_size: 0,
            is_mnemonic: true,
        },
        Mode::Password => ui::OutputConfig {
            word_count: 0,
            password_length: cli.length.unwrap_or(default_length),
            wordlist_size: 0,
            charset_size: 90,
            is_mnemonic: false,
        },
    };

    let ((output, info, out_cfg, kdf_cfg), elapsed) = ui::show_progress(unicode_support, || {
        let final_key = kdf::derive_hierarchical(&master_secret, &layers, kdf_config)?;

        if output_config.is_mnemonic {
            let mnemonic = generator::generate_mnemonic(&final_key, output_config.word_count)?;
            Ok((mnemonic, input_info, output_config, kdf_config))
        } else {
            let password = generator::generate_password(&final_key, output_config.password_length)?;
            Ok((password, input_info, output_config, kdf_config))
        }
    })?;

    let display_options = ui::DisplayOptions {
        unicode_support,
        color_support,
        quiet: cli.quiet,
    };

    ui::display_output(
        &output,
        &info,
        &out_cfg,
        &kdf_cfg,
        elapsed,
        &display_options,
    );

    Ok(())
}
