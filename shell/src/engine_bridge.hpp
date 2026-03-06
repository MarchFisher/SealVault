#pragma once

#include <string>

// 调用 Rust engine CLI 执行加密。
// 返回 true 表示子进程退出码为 0。
bool run_encrypt(const std::wstring& input_path, const std::wstring& password);
