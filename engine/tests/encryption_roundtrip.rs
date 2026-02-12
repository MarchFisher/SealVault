//! SealVault 加密/解密流程测试
//!
//! 这个文件是对加密解密流程的测试，测试了加密解密的正确性，以及密码错误时的错误处理。
//!
//! 测试流程：
//! 1. 创建临时目录，并在其中创建输入文件，以及加密文件、解密文件。
//! 2. 写入输入文件，并使用正确的密码加密文件。
//! 3. 解密加密文件，并验证解密结果与输入文件相同。
//! 4. 使用错误的密码解密加密文件，并验证解密失败。
//! 5. 测试解密失败时的错误处理。

use std::fs;
use std::io::Write;

use tempfile::tempdir;

/// 测试加密解密流程
#[test]
fn encrypt_decrypt_roundtrip() {
    let temp_dir = tempdir().expect("create temp dir");
    let input_path = temp_dir.path().join("input.txt");
    let encrypted_path = temp_dir.path().join("output.svlt");
    let decrypted_path = temp_dir.path().join("decrypted.txt");

    let plaintext = b"sealvault test payload";
    {
        let mut input_file = fs::File::create(&input_path).expect("create input");
        input_file.write_all(plaintext).expect("write plaintext");
    }

    engine::encrypt(&input_path, &encrypted_path, "test-password").expect("encrypt file");
    engine::decrypt(&encrypted_path, &decrypted_path, "test-password").expect("decrypt file");

    let decrypted = fs::read(&decrypted_path).expect("read decrypted");
    assert_eq!(decrypted, plaintext);
}

/// 测试加密解密流程(AES-256-GCM)
#[test]
fn encrypt_decrypt_roundtrip_with_aes_256_gcm() {
    // 验证 AES-256-GCM 模式也能完成端到端 round-trip。
    let temp_dir = tempdir().expect("create temp dir");
    let input_path = temp_dir.path().join("input.txt");
    let encrypted_path = temp_dir.path().join("output_aes.svlt");
    let decrypted_path = temp_dir.path().join("decrypted.txt");

    let plaintext = b"sealvault aes mode payload";
    {
        let mut input_file = fs::File::create(&input_path).expect("create input");
        input_file.write_all(plaintext).expect("write plaintext");
    }

    engine::encrypt_with_algorithm(
        &input_path,
        &encrypted_path,
        "test-password",
        engine::AeadAlgorithm::Aes256Gcm,
    )
    .expect("encrypt file with aes");

    engine::decrypt(&encrypted_path, &decrypted_path, "test-password").expect("decrypt file");

    let decrypted = fs::read(&decrypted_path).expect("read decrypted");
    assert_eq!(decrypted, plaintext);
}

/// 测试解密失败(missing key)时的错误处理
#[test]
fn decrypt_with_wrong_password_fails() {
    let temp_dir = tempdir().expect("create temp dir");
    let input_path = temp_dir.path().join("input.txt");
    let encrypted_path = temp_dir.path().join("output.svlt");
    let decrypted_path = temp_dir.path().join("decrypted.txt");

    {
        let mut input_file = fs::File::create(&input_path).expect("create input");
        input_file
            .write_all(b"sealvault auth fail")
            .expect("write plaintext");
    }

    engine::encrypt(&input_path, &encrypted_path, "correct-password").expect("encrypt file");

    let result = engine::decrypt(&encrypted_path, &decrypted_path, "wrong-password");
    assert!(result.is_err(), "expected decrypt to fail");
}

/// 测试解密失败(invalid header magic)时的错误处理
#[test]
fn decrypt_rejects_invalid_header_magic() {
    let temp_dir = tempdir().expect("create temp dir");
    let bad_path = temp_dir.path().join("bad.svlt");
    let output_path = temp_dir.path().join("output.txt");

    fs::write(&bad_path, b"not a sealvault file").expect("write bad file");

    let result = engine::decrypt(&bad_path, &output_path, "password");
    assert!(result.is_err(), "expected invalid header");
}
