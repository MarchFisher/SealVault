//! SealVault 命令行入口
//!
//! 提供最小可用的 CLI：
//!
//! 用法：
//!   cargo run -- encrypt <input> <output> <password>
//!   cargo run -- decrypt <input> <output> <password>
//!
//! 设计原则：
//! - 不依赖 clap / structopt
//! - 参数解析保持“一眼能懂”
//! - 所有实际逻辑都委托给 command 模块

mod crypto;
mod format;
mod error;

use std::{env, path::Path};
use std::process::exit;

mod encrypt;
mod decrypt;

fn print_usage() {
    eprintln!(
        "Usage:\n  \
         sealvault encrypt <input> <output> <password>\n  \
         sealvault decrypt <input> <output> <password>"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 5 {
        print_usage();
        exit(1);
    }

    let command = &args[1];
    let input = Path::new(&args[2]);
    let output = Path::new(&args[3]);
    let password = &args[4];

    let result = match command.as_str() {
        "encrypt" => encrypt::encrypt_file(input, output, password),
        "decrypt" => decrypt::decrypt_file(input, output, password),
        _ => {
            print_usage();
            exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        exit(1);
    }
}
