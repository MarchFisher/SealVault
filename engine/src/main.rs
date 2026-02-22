//! SealVault 命令行入口
//!
//! 提供最小可用的 CLI：
//!
//! 用法：
//!   cargo run -- encrypt|e <input> [output] <password> [algorithm]
//!   cargo run -- decrypt|d <input> [output] <password>
//!   cargo run -- encrypt-folder|ef <input_dir> [output_dir] <password> [algorithm]
//!   cargo run -- decrypt-folder|df <input_dir> [output_dir] <password> [algorithm]
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

use std::env;
use std::path::{Path, PathBuf};
use std::process::exit;

mod decrypt;
mod encrypt;
mod folder;

use crate::algorithm::AeadAlgorithm;

fn print_usage() {
    eprintln!(
        "Usage:\n  \
         sealvault encrypt|e <input> [output] <password> [algorithm]\n  \
         sealvault decrypt|d <input> [output] <password>\n  \
         sealvault encrypt-folder|ef <input_dir> [output_dir] <password> [algorithm]\n  \
         sealvault decrypt-folder|df <input_dir> [output_dir] <password> [algorithm]"
    );
}

fn default_encrypted_output(input: &Path) -> PathBuf {
    PathBuf::from(format!("{}.svlt", input.display()))
}

fn default_decrypted_output(input: &Path) -> Result<PathBuf, &'static str> {
    if input.extension().and_then(|v| v.to_str()) != Some("svlt") {
        return Err("decrypt input must end with .svlt when output is omitted");
    }

    let mut output = input.to_path_buf();
    output.set_extension("");
    Ok(output)
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

    if args.len() < 2 {
        print_usage();
        exit(1);
    }

    let command = args[1].as_str();

    let result = match command {
        "encrypt" | "e" => {
            if args.len() != 4 && args.len() != 5 && args.len() != 6 {
                print_usage();
                exit(1);
            }

            let input = Path::new(&args[2]);
            let (output, password, algorithm_arg) = if args.len() == 4 {
                (default_encrypted_output(input), &args[3], None)
            } else {
                let algorithm_arg = if args.len() == 6 { args.get(5) } else { None };
                (PathBuf::from(&args[3]), &args[4], algorithm_arg)
            };

            let algorithm = match parse_algorithm(algorithm_arg) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: {e}");
                    print_usage();
                    exit(1);
                }
            };
            encrypt::encrypt_file_with_algorithm(input, &output, password, algorithm)
        }
        "decrypt" | "d" => {
            if args.len() != 4 && args.len() != 5 {
                print_usage();
                exit(1);
            }

            let input = Path::new(&args[2]);
            let (output, password) = if args.len() == 4 {
                let output = match default_decrypted_output(input) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        print_usage();
                        exit(1);
                    }
                };
                (output, &args[3])
            } else {
                (PathBuf::from(&args[3]), &args[4])
            };
            decrypt::decrypt_file(input, &output, password)
        }
        "encrypt-folder" | "ef" => {
            if args.len() != 4 && args.len() != 5 && args.len() != 6 {
                print_usage();
                exit(1);
            }

            let input = Path::new(&args[2]);
            let (output, password, algorithm_arg) = if args.len() == 4 {
                (default_encrypted_output(input), &args[3], None)
            } else {
                let algorithm_arg = if args.len() == 6 { args.get(5) } else { None };
                (PathBuf::from(&args[3]), &args[4], algorithm_arg)
            };

            let algorithm = match parse_algorithm(algorithm_arg) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: {e}");
                    print_usage();
                    exit(1);
                }
            };
            folder::encrypt_folder(input, &output, password, algorithm)
        }
        "decrypt-folder" | "df" => {
            if args.len() != 4 && args.len() != 5 && args.len() != 6 {
                print_usage();
                exit(1);
            }

            let input = Path::new(&args[2]);
            let (output, password, algorithm_arg) = if args.len() == 4 {
                let output = match default_decrypted_output(input) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("Error: {e}");
                        print_usage();
                        exit(1);
                    }
                };
                (output, &args[3], None)
            } else {
                let algorithm_arg = if args.len() == 6 { args.get(5) } else { None };
                (PathBuf::from(&args[3]), &args[4], algorithm_arg)
            };

            let algorithm = match parse_algorithm(algorithm_arg) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("Error: {e}");
                    print_usage();
                    exit(1);
                }
            };
            folder::decrypt_folder(input, &output, password, algorithm)
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
