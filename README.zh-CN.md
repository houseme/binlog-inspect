# binlog-inspect

[![Crates.io](https://img.shields.io/crates/v/binlog-inspect.svg)](https://crates.io/crates/binlog-inspect)
[![Documentation](https://docs.rs/binlog-inspect/badge.svg)](https://docs.rs/binlog-inspect)
[![CI](https://github.com/houseme/binlog-inspect/actions/workflows/ci.yml/badge.svg)](https://github.com/houseme/binlog-inspect/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-stable-orange.svg)](#rust-toolchain-compatibility)

[English](README.md) | 简体中文

`binlog-inspect` 是用于检查明文 MySQL 二进制日志的 Rust 命令行工具和库。它逐事件流式读取文件，将事件解码为与底层库解耦的类型化模型（含 tagged/匿名 GTID、`previous_gtids`、表映射和行镜像），并提供 JSON Lines、文本和 CSV 输出。

## 功能

- 读取一个或多个本地 binlog，支持 `-` 从标准输入读取；启用 `remote` feature 后也可下载 HTTP(S) 文件。
- 事件类型全面分类（27 种）：类型化解码 format_description、table_map、query、xid、gtid（tagged，`uuid:tag:gno`）、anonymous_gtid、previous_gtids、rotate、stop、rows_query、incident、intvar、partial_update_rows（before 镜像 + 应用 JSON 差异）及 write/update/delete 行事件；命名但未解码的事件保留类型与 `raw_len`。
- 行镜像保留列位置、缺失列与 SQL NULL 的区分，数值附带 MySQL 列类型与 signedness。
- 多维过滤：按事件类型、`database.table`、字节偏移区间（`--start-position`/`--stop-position`）、时间区间（`--start-datetime`/`--stop-datetime`）与精确 GTID（`--include-gtid`）筛选，行事件保留前后镜像。
- `--stats` 输出单个 JSON 统计对象（文件数、事件数、字节数、事务数、按类型与按表计数、错误数）；`--completions` 生成 shell 补全脚本。
- 原始事件缓冲区默认上限为 64 MiB；敌意构造的事件头与表映射元数据在解码前预校验；验证支持的事件 CRC32 校验和。当前源码提供 `visit_events`，供库调用者逐个消费压缩事务内层事件。
- `--output` 原子写入：unix 权限 0600，绝不覆盖已存在的文件。
- 退出码分层：0 成功、1 硬错误、2 用法错误、3 部分解析失败。

## 安装与快速开始

从 crates.io 安装（需要 Rust 1.88 或更新版本——MSRV 已验证并由 CI 强制执行；项目使用 Rust 2024 edition）：

```sh
cargo install binlog-inspect --locked
```

或从源码构建、安装：

```sh
cargo build --locked --release
# 或安装到 ~/.cargo/bin
cargo install --path .
```

以下命令在项目根目录执行，使用 `Cargo.lock` 中锁定的依赖：

```sh
./target/release/binlog-inspect path/to/mysql-bin.000001
cat path/to/mysql-bin.000001 | ./target/release/binlog-inspect - --events xid
./target/release/binlog-inspect path/to/mysql-bin.000001 --events query,xid --format text
./target/release/binlog-inspect path/to/mysql-bin.000001 --table app.orders --format csv --output rows.csv
./target/release/binlog-inspect path/to/mysql-bin.000001 --stats
```

默认输出 JSON Lines 到标准输出。退出码含义见[使用文档](docs/USAGE.zh-CN.md#退出码)；部分解析失败时输出包含成功解析的前缀，请检查退出状态。`--output` 只创建新文件，不覆盖已有文件。输出可能包含业务数据，应存放在可信位置。

远程下载需要单独启用 feature：

```sh
cargo run --locked --features remote -- --url https://example.com/mysql-bin.000001
```

<a id="rust-toolchain-compatibility" name="rust-toolchain-compatibility"></a>

## Rust 工具链兼容性

需要 Rust 1.88 或更新版本（MSRV 已验证，并由专门的 CI job 强制执行）；项目使用 Rust 2024 edition。

## 限制

- 仅支持明文文件；加密 binlog 会被明确拒绝，HTTP 下载不会解密，也不是 MySQL 复制协议。
- 压缩事务（code 40）已安全解码：压缩头在解码前预校验，解压流式且有界（声明大小 + 余量；超过 1 GiB 的声明直接拒绝），内层事件与解析器共享表映射状态。
- `partial_update_rows` 解码 before 镜像，并将 after 的 JSON 差异应用到 before 值上；无法应用的差异以带保留差异与原因的 `partial_json` 丢失标记呈现。
- 解码后的 JSON 值受资源限制：嵌套超过 MySQL 100 层容器上限、以及按 1,000,000 节点预算会过度展开的敌意别名形状，都会返回携带偏移的解析错误，畸形的 opaque `NEWDECIMAL` 成员亦然。opaque jsonb 成员按文档规则渲染——十进制与日期/时间值渲染为文本形式，其他 opaque 类型渲染为 `base64:type<id>:<data>` 字符串。
- Rotate 事件只报告不跟随，需自行列出下一个文件。
- MariaDB 专有事件类型（160+）保持 `unknown`；`rand`、`user_var` 等命名类型只保留类型与 `raw_len`。
- 单个事件默认上限 64 MiB；CLI 可用 `--max-event-size` 调整（不超过 1 GiB 检查上限），库调用者可用 `with_max_event_size`。
- 当前依赖解码器对表映射中的原始 `VAR_STRING` 和 `TYPED_ARRAY` 列返回明确的不支持错误。
- 列名和数值符号信息取决于 binlog 元数据；字节以十六进制输出，不推断字符集。
- 兼容性尚未覆盖所有服务端版本、事件和列类型，成功退出不意味着所有事件都已理解。

## 文档与开发

- [中文使用文档](docs/USAGE.zh-CN.md) | [English usage guide](docs/USAGE.en.md)
- [设计文档](DESIGN.md)；[构建与验证记录](EXECUTION.md)
- [ROADMAP](ROADMAP.md)；[更新日志](CHANGELOG.md)

```sh
cargo clippy --locked --all-targets -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked
cargo test --locked --all-features
cargo build --locked --no-default-features
cargo build --locked --all-features
```
