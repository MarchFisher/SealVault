// Shell 程序入口：仅负责命令分发。
//
// 设计目标：
// - main.cpp 保持轻量，便于审查和后续扩展。
// - 将注册表操作与 engine 调用细节放到独立模块。

#include "engine_bridge.hpp"
#include "registry_menu.hpp"
#include "windows_utils.hpp"

#include <iostream>
#include <string>

namespace {

void print_usage() {
    std::wcout
        << L"用法:\n"
        << L"  svshell register           # 注册右键菜单（当前用户）\n"
        << L"  svshell unregister         # 注销右键菜单\n"
        << L"  svshell encrypt <path>     # 执行加密（供右键 command 调用）\n";
}

int handle_register() {
    auto self = module_path();
    if (!self) {
        std::wcerr << L"无法定位 svshell.exe。" << std::endl;
        return 1;
    }

    // Explorer 将选中项路径传入 %1，外层引号由我们显式添加，避免空格路径解析问题。
    std::wstring action = quote_arg(*self) + L" encrypt \"%1\"";
    if (!register_menu(action)) {
        std::wcerr << L"右键菜单注册失败。" << std::endl;
        return 1;
    }

    std::wcout << L"右键菜单注册完成。" << std::endl;
    return 0;
}

int handle_encrypt(wchar_t* argv[], int argc) {
    if (argc < 3) {
        std::wcerr << L"缺少待加密路径。" << std::endl;
        return 1;
    }

    std::wstring password;
    std::wcout << L"请输入加密密码（输入可见）: ";
    std::getline(std::wcin, password);

    if (password.empty()) {
        std::wcerr << L"密码不能为空。" << std::endl;
        return 1;
    }

    return run_encrypt(argv[2], password) ? 0 : 1;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::wstring command = argv[1];
    if (command == L"register") {
        return handle_register();
    }

    if (command == L"unregister") {
        unregister_menu();
        std::wcout << L"右键菜单已注销。" << std::endl;
        return 0;
    }

    if (command == L"encrypt") {
        return handle_encrypt(argv, argc);
    }

    print_usage();
    return 1;
}
