// Windows 通用辅助函数：路径定位与参数转义。

#include "windows_utils.hpp"

#include <windows.h>

#include <filesystem>
#include <vector>

std::wstring quote_arg(const std::wstring& arg) {
    std::wstring quoted = L"\"";
    for (wchar_t ch : arg) {
        if (ch == L'\"') {
            quoted += L"\\\"";
        } else {
            quoted += ch;
        }
    }
    quoted += L"\"";
    return quoted;
}

std::optional<std::wstring> module_path() {
    std::vector<wchar_t> buffer(MAX_PATH);

    while (true) {
        DWORD written = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (written == 0) {
            return std::nullopt;
        }

        if (written < buffer.size() - 1) {
            return std::wstring(buffer.data(), written);
        }

        buffer.resize(buffer.size() * 2);
    }
}

std::optional<std::wstring> sibling_engine_path() {
    auto self = module_path();
    if (!self) {
        return std::nullopt;
    }

    std::filesystem::path exe(*self);
    auto engine = exe.parent_path() / L"sealvault.exe";
    return engine.wstring();
}
