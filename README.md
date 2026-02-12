# SealVault

SealVault 是一个正在持续迭代的文件加密引擎项目，当前仓库主要包含 **Rust 实现的 engine 核心**，已经可以进行文件与目录的端到端加解密（CLI + 库接口）。

> 当前阶段定位：
> - ✅ 核心加密流程可用
> - ✅ 自定义 `.svlt` 格式已落地（v1 Header + Stream）
> - ✅ 单文件与目录递归加解密可用
> - 🚧 仍处于“引擎优先”阶段，UI / Shell 生态尚未展开

---

## 当前能力（已实现）

### 1) 单文件加密与解密

- 支持将任意文件加密为 `.svlt`。
- 支持将 `.svlt` 解密回原始文件。
- 采用流式 chunk 处理，不把整个文件一次性读入内存。

### 2) 目录递归加密与解密

- 支持递归遍历目录并保持相对路径结构。
- 加密后文件名追加 `.svlt` 后缀。
- 解密时仅处理 `.svlt` 文件并去除后缀恢复原名。
- 包含路径安全检查（拒绝不安全组件），降低路径穿越风险。

### 3) 双算法支持（可选）

当前 AEAD 算法：

- `xchacha20poly1305`（默认）
- `aes-256-gcm`

算法标识会写入文件 Header，解密端按 Header 中算法解析。

### 4) 原子写出保障

加密与解密输出均使用“临时文件写完后再 rename 替换”的原子写策略，降低失败时污染目标文件的风险。

---

## 快速开始

### 环境

- Rust stable（建议使用较新稳定版）

### 运行测试

```bash
cd engine
cargo test
```

### CLI 用法

在 `engine/` 目录：

```bash
# 单文件加密（默认 xchacha20poly1305）
cargo run -- encrypt <input> <output.svlt> <password>

# 单文件加密（指定算法）
cargo run -- encrypt <input> <output.svlt> <password> aes-256-gcm

# 单文件解密
cargo run -- decrypt <input.svlt> <output> <password>

# 目录加密
cargo run -- encrypt-folder <input_dir> <output_dir> <password> [algorithm]

# 目录解密
cargo run -- decrypt-folder <input_dir> <output_dir> <password> [algorithm]
```

> 注意：`decrypt-folder` 的算法参数当前不会驱动解密逻辑，实际以每个 `.svlt` 文件 Header 中记录的算法为准。

---

## 项目结构（当前）

```text
SealVault/
├── engine/                         # Rust 核心引擎（当前主战场）
│   ├── src/
│   │   ├── encrypt.rs              # 文件加密流程
│   │   ├── decrypt.rs              # 文件解密流程
│   │   ├── folder.rs               # 目录加解密流程
│   │   ├── format/                 # .svlt 格式（header + stream）
│   │   ├── crypto/                 # KDF / AEAD 辅助模块
│   │   ├── algorithm/              # 算法实现与枚举
│   │   └── fs/atomic.rs            # 原子写入
│   └── tests/                      # roundtrip 与错误路径测试
├── docs/
│   └── stream_format_specification.md
└── AI_README.md                    # 给 AI 的历史上下文（非用户文档）
```

---

## 安全与工程说明（当前阶段）

- KDF 使用 Argon2id，按文件随机 salt 派生 32-byte key。
- Stream 按 chunk 加密，并使用 `chunk_index` 作为 AAD，防重排。
- Header 校验失败、chunk 校验失败、错误密码等场景会直接报错。
- 解密失败时不会覆盖已有输出内容（依赖原子写语义）。

---

## 当前边界 / 非目标（现阶段）

当前仓库 **尚未** 提供：

- 完整桌面 GUI
- 完整 Shell 子项目（独立仓库级别）
- 稳定版对外格式承诺（v1 仍可根据审计与实现反馈演进）

如果你要在此基础上继续开发，建议优先顺序：

1. 保持格式兼容性策略清晰（变更即版本化）
2. 继续补齐对抗性测试（损坏输入、恶意路径、超大文件）
3. 再推进 CLI 体验与上层集成

---

## 许可

本项目采用 `LICENSE` 中声明的开源许可。