#pragma once

#include <string>

// 注册右键菜单（当前用户 HKCU）。
bool register_menu(const std::wstring& action);

// 注销右键菜单。
bool unregister_menu();
