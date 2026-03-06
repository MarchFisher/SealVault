// Windows 右键菜单注册/注销实现。
//
// 当前按“最小可用原型”原则，仅写入 HKCU（当前用户）范围，
// 避免需要管理员权限。

#include "registry_menu.hpp"

#include <windows.h>

#include <iostream>

namespace {

constexpr wchar_t kMenuText[] = L"SealVault 加密 (.svlt)";
constexpr wchar_t kMenuKeyName[] = L"SealVault.Encrypt";

bool write_menu_for(const std::wstring& root, const std::wstring& command) {
    std::wstring key_path = root + L"\\shell\\" + kMenuKeyName;

    HKEY key = nullptr;
    LONG result = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        key_path.c_str(),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &key,
        nullptr
    );

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"创建注册表键失败: " << key_path << L", code=" << result << std::endl;
        return false;
    }

    result = RegSetValueExW(
        key,
        nullptr,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(kMenuText),
        static_cast<DWORD>((wcslen(kMenuText) + 1) * sizeof(wchar_t))
    );

    RegCloseKey(key);

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"写入菜单文本失败: code=" << result << std::endl;
        return false;
    }

    std::wstring cmd_key_path = key_path + L"\\command";
    HKEY cmd_key = nullptr;
    result = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        cmd_key_path.c_str(),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &cmd_key,
        nullptr
    );

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"创建 command 键失败: " << cmd_key_path << L", code=" << result << std::endl;
        return false;
    }

    result = RegSetValueExW(
        cmd_key,
        nullptr,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(command.c_str()),
        static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t))
    );

    RegCloseKey(cmd_key);

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"写入 command 失败: code=" << result << std::endl;
        return false;
    }

    return true;
}

void delete_menu_for(const std::wstring& root) {
    std::wstring cmd_key = root + L"\\shell\\" + kMenuKeyName + L"\\command";
    std::wstring top_key = root + L"\\shell\\" + kMenuKeyName;
    RegDeleteTreeW(HKEY_CURRENT_USER, cmd_key.c_str());
    RegDeleteTreeW(HKEY_CURRENT_USER, top_key.c_str());
}

}  // namespace

bool register_menu(const std::wstring& action) {
    bool ok = true;
    ok &= write_menu_for(L"Software\\Classes\\*", action);
    ok &= write_menu_for(L"Software\\Classes\\Directory", action);
    return ok;
}

bool unregister_menu() {
    delete_menu_for(L"Software\\Classes\\*");
    delete_menu_for(L"Software\\Classes\\Directory");
    return true;
}
