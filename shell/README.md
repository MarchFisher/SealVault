# SealVault Shell（C++）

该目录提供一个 **Windows 右键菜单桥接程序**（`svshell`），用于把现有 Rust `engine` 的加密能力挂接到资源管理器右键。

## 代码拆分（当前实现）

- `src/main.cpp`：仅做命令分发（`register` / `unregister` / `encrypt`）。
- `src/registry_menu.cpp`：右键菜单注册/注销（注册表写入）。
- `src/engine_bridge.cpp`：调用 `sealvault.exe encrypt` / `encrypt-folder`。
- `src/windows_utils.cpp`：通用 Windows 路径与参数转义工具。

## 当前实现行为（基于代码）

- `svshell register`
  - 在当前用户注册表（`HKCU\Software\Classes`）下注册右键菜单：
    - `*`（普通文件）
    - `Directory`（目录）
- `svshell encrypt <path>`
  - 运行时要求输入密码。
  - 若 `<path>` 是文件，则调用：`sealvault.exe encrypt ...`
  - 若 `<path>` 是目录，则调用：`sealvault.exe encrypt-folder ...`
- `svshell unregister`
  - 删除上述右键菜单项。

> 注意：`svshell` 通过调用同目录下的 `sealvault.exe` 工作。部署时请把两者放在同一目录。

## 多语言（Rust + C++）编译与运行

### 1) 编译 Rust engine（生成 `sealvault.exe`）

```powershell
cd engine
cargo build --release
```

产物通常在：`engine\target\release\sealvault.exe`

### 2) 编译 C++ shell（生成 `svshell.exe`）

```powershell
cd ..
cmake -S shell -B build-shell
cmake --build build-shell --config Release
```

产物通常在：`build-shell\Release\svshell.exe`（MSVC 多配置）或 `build-shell\svshell.exe`（单配置生成器）。

### 3) 部署（关键）

将 `sealvault.exe` 和 `svshell.exe` 放在同一目录，例如：

```text
C:\SealVault\sealvault.exe
C:\SealVault\svshell.exe
```

### 4) 注册与使用

```powershell
C:\SealVault\svshell.exe register
```

随后在资源管理器中右键文件或目录，点击 **SealVault 加密 (.svlt)**，输入密码即可。

移除菜单：

```powershell
C:\SealVault\svshell.exe unregister
```

## 安全说明

- 当前原型会将密码作为命令行参数传给 `sealvault.exe`，这在 Windows 上可能被同机高权限进程观察到。
- 该风险来自当前 engine CLI 输入模型（密码参数）与快速集成目标，后续可考虑改为受控 stdin/IPC 方案以减少暴露面。
