//! SealVault 命令行入口
//!
//! 提供最小可用的 CLI：
//!
//! 用法：
//!   cargo run -- encrypt <input> <output> <password> [algorithm]
//!   cargo run -- decrypt <input> <output> <password>
//!   cargo run -- encrypt-folder <input_dir> <output_dir> <password> [algorithm]
//!   cargo run -- decrypt-folder <input_dir> <output_dir> <password> [algorithm]
//!
//! 设计原则：
//! - 不依赖 clap / structopt
//! - 参数解析保持“一眼能懂”
//! - 所有实际逻辑都委托给 command 模块

mod algorithm;
mod crypto;
mod error;
mod format;
mod fs;

use std::process::exit;
use std::{env, path::Path};

mod decrypt;
mod encrypt;
mod folder;

use crate::algorithm::AeadAlgorithm;

fn print_usage() {
    eprintln!(
        "Usage:\n  \
         sealvault encrypt <input> <output> <password> [algorithm]\n  \
         sealvault decrypt <input> <output> <password>\n  \
         sealvault encrypt-folder <input_dir> <output_dir> <password> [algorithm]\n  \
         sealvault decrypt-folder <input_dir> <output_dir> <password> [algorithm]"
    );
}

fn parse_algorithm(arg: Option<&String>) -> Result<AeadAlgorithm, &'static str> {
    match arg.map(String::as_str) {
        None => Ok(AeadAlgorithm::XChaCha20Poly1305),
        Some("xchacha20") | Some("xchacha20poly1305") => Ok(AeadAlgorithm::XChaCha20Poly1305),
        Some("aes256gcm") | Some("aes-256-gcm") => Ok(AeadAlgorithm::Aes256Gcm),
        Some(_) => Err("unsupported algorithm"),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 5 || args.len() > 6 {
        print_usage();
        exit(1);
    }

    let command = &args[1];
    let input = Path::new(&args[2]);
    let output = Path::new(&args[3]);
    let password = &args[4];

    let result = match command.as_str() {
        "encrypt" => {
            let algorithm = match parse_algorithm(args.get(5)) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: {e}");
                    print_usage();
                    exit(1);
                }
            };
            encrypt::encrypt_file_with_algorithm(input, output, password, algorithm)
        }
        "decrypt" => decrypt::decrypt_file(input, output, password),
        "encrypt-folder" => {
            let algorithm = match parse_algorithm(args.get(5)) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: {e}");
                    print_usage();
                    exit(1);
                }
            };
            folder::encrypt_folder(input, output, password, algorithm)
        }
        "decrypt-folder" => {
            let algorithm = match parse_algorithm(args.get(5)) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: {e}");
                    print_usage();
                    exit(1);
                }
            };
            folder::decrypt_folder(input, output, password, algorithm)
        }
        _ => {
            print_usage();
            exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        exit(1);
    }
}
