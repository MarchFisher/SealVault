#pragma once

#include <optional>
#include <string>

// 为 CreateProcess 命令行参数添加引号并转义内部引号。
std::wstring quote_arg(const std::wstring& arg);

// 获取当前模块路径（svshell.exe）。
std::optional<std::wstring> module_path();

// 获取与 svshell.exe 同目录的 sealvault.exe 路径。
std::optional<std::wstring> sibling_engine_path();
