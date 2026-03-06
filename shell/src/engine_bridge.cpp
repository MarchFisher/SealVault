// 负责桥接到 Rust engine CLI。
//
// 注意：这里不会直接链接或调用 Rust lib.rs 导出的函数，
// 而是通过启动 sealvault.exe 子进程复用 engine 的既有 CLI 逻辑。

#include "engine_bridge.hpp"

#include "windows_utils.hpp"

#include <windows.h>

#include <filesystem>
#include <iostream>
#include <sstream>

bool run_encrypt(const std::wstring& input_path, const std::wstring& password) {
    auto engine_path = sibling_engine_path();
    if (!engine_path) {
        std::wcerr << L"无法解析 svshell.exe 路径。" << std::endl;
        return false;
    }

    std::filesystem::path input(input_path);
    const bool is_file = std::filesystem::is_regular_file(input);
    const bool is_dir = std::filesystem::is_directory(input);

    if (!is_file && !is_dir) {
        std::wcerr << L"仅支持文件或目录加密: " << input_path << std::endl;
        return false;
    }

    // 输出规则与此前原型保持一致：追加 .svlt。
    std::wstring output = input_path + L".svlt";
    const wchar_t* subcmd = is_dir ? L"encrypt-folder" : L"encrypt";

    std::wstringstream cmd;
    cmd << quote_arg(*engine_path) << L" " << subcmd << L" " << quote_arg(input_path) << L" "
        << quote_arg(output) << L" " << quote_arg(password);

    std::wstring cmdline = cmd.str();
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(
        nullptr,
        cmdline.data(),
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        nullptr,
        &si,
        &pi
    );

    if (!ok) {
        std::wcerr << L"启动 sealvault.exe 失败，错误码: " << GetLastError() << std::endl;
        return false;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (exit_code != 0) {
        std::wcerr << L"加密失败，sealvault.exe 退出码: " << exit_code << std::endl;
        return false;
    }

    std::wcout << L"加密成功: " << output << std::endl;
    return true;
}
