# SealVault v1 Stream Format 说明

> 版本：**1**
> 
> 状态：**稳定（提议）**
> 
> 范围：**单文件加密（.svlt）**
> 

---

## 1. 设计目标

SealVault v1 Stream 设计用于：

- 支持 **任意大小文件** 的流式加密
- 不加载整文件到内存
- 保证：
    - 机密性（Confidentiality）
    - 完整性（Integrity）
    - 防篡改（Tamper Detection）
- 为未来功能预留空间：
    - 文件夹封装
    - 并行解密
    - 版本升级

---

## 2. 整体文件结构（高层）

```
+----------------+
|   Header       |  固定长度 / 可扩展
+----------------+
|   Stream       |  由多个加密块组成
+----------------+
```

Header 定义算法、参数、salt 等

Stream 定义 **真正的加密数据流**

---

## 3. Stream 总体结构

```
Stream :=
    Chunk[0]
    Chunk[1]
    ...
    Chunk[N-1]
```

每个 Chunk **独立认证**，解密失败立即终止。

---

## 4. Chunk 结构（字节级）

```
Chunk :=
    +------------+----------------------+------------+
    | Length (4) | Ciphertext (Length) | Tag (16)   |
    +------------+----------------------+------------+
```

| 字段 | 大小 | 说明 |
| --- | --- | --- |
| Length | 4 bytes | **大端**无符号整数，表示 Ciphertext 长度 |
| Ciphertext | N bytes | AEAD 加密后的数据 |
| Tag | 16 bytes | AEAD 认证标签 |

---

## 5. Chunk 明文内容（加密前）

```
PlaintextChunk :=
    Data
```

- `Data` 为原始文件字节
- **不包含任何额外字段**
- 长度由 Length 间接决定

---

## 6. Chunk Size 规则

- 推荐明文 chunk 大小：**64 KiB**
- 最后一个 chunk：
    - 长度 ≤ 64 KiB
- 允许实现自定义大小，但：
    - 必须写入 Header
    - 解密端必须按 Header 解析

---

## 7. AEAD 参数约定

### 7.1 使用算法

- 算法：**XChaCha20-Poly1305**
- Key：来自 KDF（见 header）

---

### 7.2 Nonce 生成规则（关键）

```
Nonce = base_nonce (24 bytes) XOR chunk_index
```

- `base_nonce`：
    - 在 Header 中生成并存储
- `chunk_index`：
    - 64-bit 递增计数器
    - 从 0 开始
    - 写入 nonce 的低 8 bytes

**保证：**

- 每个 chunk nonce 唯一
- 不需要在 stream 中存储 nonce

---

### 7.3 AAD（Additional Authenticated Data）

```
AAD = chunk_index (8 bytes, big-endian)
```

- 不加密
- 参与认证
- 防止块重排 / 插入攻击

---

## 8. 结束条件（EOF）

- Stream **无特殊结束标记**
- 解密器：
    - 读取 Length
    - 若无法完整读取 Chunk → 失败
    - 直到文件结束

---

## 9. 错误处理策略

| 情况 | 行为 |
| --- | --- |
| Tag 校验失败 | 立即终止并报错 |
| Length 异常（过大） | 立即终止 |
| 提前 EOF | 视为文件损坏 |

---

## 10. 安全属性总结

- ✔ 每块独立认证
- ✔ 不可静默篡改
- ✔ 不可块重排
- ✔ 支持大文件
- ✔ 可流式处理

---

## 11. v1 限制（明确声明）

SealVault v1 **不支持**：

- 并行解密
- 随机访问
- 文件夹封装
- 明文元数据

这些将在 **v2+** 解决。

---

## 12. 未来扩展点（预留）

- Header 中新增：
    - Compression flag
    - Folder table offset
    - Metadata AEAD
- Stream chunk 变种：
    - 可变结构
    - 多段认证

---

## 13. 实现约束（给你自己看的）

> **任何实现不得偏离本规范**
> 
> 
> 若需修改 → 必须 bump version
>