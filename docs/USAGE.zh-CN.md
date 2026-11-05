# 使用文档

[English](USAGE.en.md) | [项目首页](../README.md)

## 安装与构建

本项目尚未发布到 crates.io，需从源码构建或安装。需要当前 Rust stable 工具链（项目使用 Rust 2024 edition，最低支持版本尚未验证）：

```sh
cargo install --path .        # 安装到 ~/.cargo/bin
# 或仅在项目内构建
cargo build --locked --release
./target/release/binlog-inspect --help
```

远程下载功能默认关闭，需要单独启用 `remote` feature：

```sh
cargo build --locked --release --features remote
```

也可以通过 `cargo run --locked -- [参数]` 运行；使用 URL 时，在 `--` 之前加 `--features remote`。工具至少需要一个本地文件或 URL。多个本地文件按给定顺序处理，然后按给定顺序处理 URL；每个输入都建立独立的解析状态。Rotate 事件不会自动打开下一个文件，需自行列出。

## 命令行参数

下表与 `binlog-inspect --help` 一致：

| 参数 | 说明 |
| --- | --- |
| `[FILES]...` | 本地 binlog 文件路径；`-` 表示从标准输入读取。 |
| `-f, --format <FORMAT>` | 输出格式：`jsonl`（默认）、`text` 或 `csv`。指定 `--stats` 时被忽略。 |
| `-o, --output <FILE>` | 写入新文件而非标准输出；已有文件不会被覆盖。 |
| `--events <EVENTS>` | 逗号分隔的事件类型，可重复；不指定则包含所有类型。 |
| `--table <database.table>` | 按 `database.table` 过滤，可重复；不指定则包含所有表和非表事件。 |
| `--start-position <OFFSET>` | 保留起始字节偏移 ≥ `OFFSET` 的事件（含边界）。 |
| `--stop-position <OFFSET>` | 保留起始字节偏移 < `OFFSET` 的事件（不含边界，mysqlbinlog 惯例）。 |
| `--start-datetime <DATETIME>` | 保留时间戳 ≥ `DATETIME` 的事件（含边界）。`DATETIME` 为系统时区的 `YYYY-MM-DD HH:MM:SS` 或 RFC3339 时间戳。 |
| `--stop-datetime <DATETIME>` | 保留时间戳 ≤ `DATETIME` 的事件（含边界；注意 mysqlbinlog 的 stop-datetime 不含边界）。 |
| `--include-gtid <GTID>` | 仅保留 `payload.gtid` 与 `GTID` 完全相等（`uuid:gno` 或 `uuid:tag:gno`）的 GTID 事件；可重复；不支持区间或集合运算。 |
| `--stats` | 输出单个 JSON 统计对象代替事件行：仅统计被保留的事件，全部输入处理完后输出。 |
| `--completions <SHELL>` | 输出 `bash`、`elvish`、`fish`、`powershell` 或 `zsh` 的补全脚本并退出；忽略其他参数，不打开任何输入。 |
| `--max-event-size <BYTES>` | 超过 `BYTES` 字节的单个事件按 "invalid or oversized" 拒绝（默认 67108864；不得超过 1 GiB 检查上限）。 |
| `--strict` | 任一输入出现第一个错误即中止全部（退出码 1）；不指定时错误停止当前文件，其余文件继续处理，最终退出码为 3。 |
| `--url <URL>` | HTTP(S) 文件地址，可重复；仅在构建时启用 `remote` 后可用。 |
| `--max-download-size <BYTES>` | 下载超过 `BYTES` 字节时中止（默认 4294967296）；仅在构建时启用 `remote` 后可用。 |
| `-h, --help` / `-V, --version` | 显示帮助 / 版本。 |

所有过滤器（`--events`、`--table`、位置、时间与 GTID 过滤）以 AND 组合，在解析完成后应用，不影响解析状态。

### --events 全部取值

取值与库级 `EventType` 枚举一一对应，也是 JSON 输出中 `event_type` 字段的取值：

| 取值 | 含义 |
| --- | --- |
| `format_description` | binlog 其余部分的布局描述（含服务器版本）。 |
| `table_map` | 表标识及其 schema（库名、表名、列数）。 |
| `write_rows` | 插入的行镜像。 |
| `update_rows` | 更新的前后行镜像对。 |
| `delete_rows` | 删除的行镜像。 |
| `partial_update_rows` | 部分 JSON 更新（WL#2955）；仅解码 before 镜像，after 差异不解码。 |
| `query` | SQL 语句事件。 |
| `xid` | 事务提交标识。 |
| `gtid` | 全局事务标识，支持 MySQL 8.4+ 的 tagged GTID（`uuid:tag:gno`）。 |
| `anonymous_gtid` | 匿名事务的 GTID 事件（`gtid` 为 `ANONYMOUS`）。 |
| `previous_gtids` | 当前 binlog 文件之前已提交的 GTID 集合。 |
| `rotate` | 日志轮转（只报告，不自动打开下一个文件）。 |
| `stop` | 服务器关闭标记。 |
| `rows_query` | 行事件对应的原始语句。 |
| `incident` | 复制事件丢失报告。 |
| `intvar` | 语句期整型变量赋值（AUTO_INCREMENT / LAST_INSERT_ID）。 |
| `rand` | 语句复制的随机数种子（未解码，仅类型与长度）。 |
| `user_var` | 用户变量赋值（未解码）。 |
| `begin_load_query` | 语句流之外的批量载入数据（未解码）。 |
| `execute_load_query` | 批量载入执行标记（未解码）。 |
| `heartbeat` | 复制心跳（未解码；含 code 41）。 |
| `ignorable` | 可被不识别它的读取方安全忽略的事件（未解码）。 |
| `transaction_context` | 两阶段提交事务上下文（未解码）。 |
| `view_change` | 组复制视图变更（未解码）。 |
| `xa_prepare` | XA 事务准备（未解码）。 |
| `unknown` | 本版本未命名的事件类型（含 MariaDB 专有的 160+ 类型码）。 |
| `transaction_payload` | 压缩事务 payload（WL#3549，MySQL 8）；在安全的解压限制下解码。 |

未知取值同样在参数解析期报错（退出码 2），错误消息列出全部合法值：

```text
error: invalid value 'bogus' for '--events <EVENTS>': unknown event type; valid values: format_description, table_map, write_rows, update_rows, delete_rows, partial_update_rows, query, xid, gtid, anonymous_gtid, previous_gtids, rotate, stop, rows_query, incident, intvar, rand, user_var, begin_load_query, execute_load_query, heartbeat, ignorable, transaction_context, view_change, xa_prepare, transaction_payload, unknown
```

`--table` 的值必须在第一个 `.` 处拆分为非空的库名与表名（例如 `app.orders`）；不符合时报错（退出码 2）：`invalid --table value: expected database.table`。

## 常用示例

```sh
# 多个文件、事件类型与表
./target/release/binlog-inspect mysql-bin.000001 mysql-bin.000002 --events write_rows,update_rows --table app.orders --table app.users --output changes.jsonl
# 只输出可读摘要
./target/release/binlog-inspect mysql-bin.000001 --events query,xid --format text
# 从标准输入读取
cat mysql-bin.000001 | ./target/release/binlog-inspect - --events xid
# 字节偏移窗口（start 含边界，stop 不含）
./target/release/binlog-inspect mysql-bin.000001 --start-position 4 --stop-position 1073741824
# 时间窗口与精确 GTID
./target/release/binlog-inspect mysql-bin.000001 --start-datetime "2026-01-01 00:00:00" --include-gtid 3E11FA47-71CA-11E1-9E33-C80AA9429562:23
# 输出单个 JSON 统计对象代替事件行
./target/release/binlog-inspect mysql-bin.000001 --stats
# shell 补全（bash、elvish、fish、powershell、zsh）
./target/release/binlog-inspect --completions zsh > ~/.zfunc/_binlog-inspect
# 需要 remote feature 的构建
./target/release/binlog-inspect --url https://example.com/mysql-bin.000001 --format csv --output rows.csv
```

## 退出码

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功：所有输入完整解析。 |
| `1` | 硬错误：文件无法打开、文件头无效、输出目标已存在、`--strict` 下的第一个解析错误等；立即终止，`--output` 不产生文件。 |
| `2` | CLI 用法错误：clap 参数校验失败（如未知 `--events` 值、`--table` 缺少 `.`）。 |
| `3` | 部分解析失败：默认（非 `--strict`）模式下，解析错误停止当前文件，其余文件仍被处理；错误逐文件（含路径与偏移）汇总输出到标准错误。 |

`--strict` 的实际语义是：任何输入上的第一个错误都会中止全部处理（退出码 1）；不指定时错误只终止当前文件。退出码 3 时输出包含各文件成功解析的前缀（有意保留，便于排查）；`--output` 文件会正常发布，请按需删除。硬错误（退出码 1）时不残留任何输出文件。

```text
error: the following binlogs could not be fully parsed:
  mysql-bin.000001: binlog error at offset 31: invalid or oversized event
```

## 输出格式

- `jsonl`：每个匹配事件一个 JSON 对象。多个输入的输出没有附加源文件名；需要归属信息时请分别运行。
- `text`：每事件一行，格式为 `{timestamp} {event_type} server={server_id} pos={log_pos} {payload JSON}`。
- `csv`：表头为 `timestamp,event_type,database,table,before,after`。只有已解析的行事件（`kind` 为 `rows`）的每个行变更产生一条记录；`partial_update_rows`、未解析表映射的行事件及所有非行事件不产生记录。镜像字段是经过 CSV 转义的 JSON 字符串，缺失镜像为 JSON `null`。

### 真实输出样例

以下样例由仓库测试夹具字节构造的合成 binlog 生成（非真实数据）：依次包含 GTID（`uuid:gno`）、Query（`SELECT 1`）、Table Map（`app.t`，1 列 `LONG`）、Write Rows（值 `42`）、XID（`123`）共 5 个事件；时间戳固定为 `1700000000`，server ID 为 7，输出为实际命令 `binlog-inspect sample.binlog` 的结果。

`--format jsonl`（默认）：

```jsonl
{"offset":4,"timestamp":1700000000,"event_type":"gtid","event_type_code":33,"server_id":7,"event_size":44,"log_pos":48,"payload":{"kind":"gtid","gtid":"11111111-1111-1111-1111-111111111111:1","tag":null}}
{"offset":48,"timestamp":1700000000,"event_type":"query","event_type_code":2,"server_id":7,"event_size":44,"log_pos":92,"payload":{"kind":"query","database":"app","sql":"SELECT 1"}}
{"offset":92,"timestamp":1700000000,"event_type":"table_map","event_type_code":19,"server_id":7,"event_size":39,"log_pos":131,"payload":{"kind":"table_map","table_id":1,"database":"app","table":"t","column_count":1}}
{"offset":131,"timestamp":1700000000,"event_type":"write_rows","event_type_code":30,"server_id":7,"event_size":36,"log_pos":167,"payload":{"kind":"rows","table_id":1,"database":"app","table":"t","changes":[{"before":null,"after":{"columns":[{"index":0,"name":"@0","mysql_type":"LONG","signedness":"unknown","value":{"type":"int","value":42}}]}}]}}
{"offset":167,"timestamp":1700000000,"event_type":"xid","event_type_code":16,"server_id":7,"event_size":27,"log_pos":194,"payload":{"kind":"xid","xid":123}}
```

`--format text`：

```text
1700000000 gtid server=7 pos=48 {"kind":"gtid","gtid":"11111111-1111-1111-1111-111111111111:1","tag":null}
1700000000 query server=7 pos=92 {"kind":"query","database":"app","sql":"SELECT 1"}
1700000000 table_map server=7 pos=131 {"kind":"table_map","table_id":1,"database":"app","table":"t","column_count":1}
1700000000 write_rows server=7 pos=167 {"kind":"rows","table_id":1,"database":"app","table":"t","changes":[{"before":null,"after":{"columns":[{"index":0,"name":"@0","mysql_type":"LONG","signedness":"unknown","value":{"type":"int","value":42}}]}}]}
1700000000 xid server=7 pos=194 {"kind":"xid","xid":123}
```

`--format csv`（只有行事件产生记录）：

```csv
timestamp,event_type,database,table,before,after
1700000000,"write_rows","app","t","null","{""columns"":[{""index"":0,""name"":""@0"",""mysql_type"":""LONG"",""signedness"":""unknown"",""value"":{""type"":""int"",""value"":42}}]}"
```

从标准输入读取同一文件（`--events xid` 过滤后）：

```jsonl
{"offset":167,"timestamp":1700000000,"event_type":"xid","event_type_code":16,"server_id":7,"event_size":27,"log_pos":194,"payload":{"kind":"xid","xid":123}}
```

样例中的列名 `@0` 是生成名称：合成表映射未携带列名元数据，真实 binlog 通常会带列名。

## 数据模型

每个 JSON 对象的公共字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `offset` | 整数 | 事件头在文件内的字节偏移。 |
| `timestamp` | 整数 | 事件头时间戳（Unix 秒）。 |
| `event_type` | 字符串 | 规范事件类型（snake_case，与 `--events` 取值一致）。 |
| `event_type_code` | 整数 | 原始 MySQL 事件类型码。 |
| `server_id` | 整数 | 来源服务器 ID。 |
| `event_size` | 整数 | 事件总大小（含头）。 |
| `log_pos` | 整数 | 事件头记录的下一事件位置。 |
| `payload` | 对象 | 解码后的事件内容，`kind` 标明类型。 |

### payload.kind 字段表

| `payload.kind` | 出现于 `event_type` | 字段 |
| --- | --- | --- |
| `format_description` | `format_description` | `server_version`：字符串，已在首个 NUL 处截断。 |
| `table_map` | `table_map` | `table_id`、`database`、`table`（字符串）、`column_count`：数字。 |
| `rows` | `write_rows` / `update_rows` / `delete_rows` | `table_id`：数字；`database`、`table`：字符串；`changes`：数组，每项 `{"before": 镜像或 null, "after": 镜像或 null}`。写入通常只有 `after`，删除通常只有 `before`，更新两者都有。 |
| `partial_update_rows` | `partial_update_rows` | `table_id`、`database`、`table`；`before`：数组，每项为完整行镜像或 `null`（镜像缺失时）。after 的 JSON 差异有意不解码。 |
| `unresolved` | `write_rows` / `update_rows` / `delete_rows` / `partial_update_rows`（无表映射时） | `table_id`：数字。 |
| `query` | `query` | `database`、`sql`：字符串。 |
| `xid` | `xid` | `xid`：数字。 |
| `gtid` | `gtid` / `anonymous_gtid` | `gtid`：字符串，格式为 `uuid:gno`（无 tag）、`uuid:tag:gno`（tagged，MySQL 8.4+）或 `ANONYMOUS`（匿名事务）；`tag`：字符串或 `null`。 |
| `previous_gtids` | `previous_gtids` | `gtid_set`：字符串，mysqlbinlog 风格的集合串（`uuid[:tag]:区间`，多个 SID 用逗号分隔）。 |
| `rotate` | `rotate` | `next_file`：字符串；`position`：数字。 |
| `stop` | `stop` | 无字段（空对象 `{}`）。 |
| `rows_query` | `rows_query` | `sql`：字符串。 |
| `incident` | `incident` | `incident_type`：字符串（如 `INCIDENT_LOST_EVENTS`，未识别的类型码为 `UNKNOWN(n)`）；`message`：字符串。 |
| `intvar` | `intvar` | `var_type`：字符串（`INVALID_INT_EVENT` / `LAST_INSERT_ID_EVENT` / `INSERT_ID_EVENT`）；`value`：数字。 |
| `transaction_payload` | `transaction_payload` | `compression`：字符串（`NONE` 或 `ZSTD`）；`uncompressed_size`：payload 头声明的数字（`NONE` 时为 `0`）；`events`：完整事件对象数组（结构与顶层事件相同），其 `offset` 从解压流起点计数，`timestamp`/`server_id` 继承压缩事件头。 |
| `unknown` | `rand`、`user_var`、`begin_load_query`、`execute_load_query`、`heartbeat`、`ignorable`、`transaction_context`、`view_change`、`xa_prepare`、`unknown` 及所有 MariaDB 专有类型 | `raw_len`：数字，保留的事件数据长度。 |

### 行镜像结构

行镜像（上表中的"镜像"）按表列顺序排列：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `columns` | 数组 | 每个表列一项，含被最小行镜像省略的列。 |

每列（`ColumnValue`）：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `index` | 数字 | 表中的零基列位置。 |
| `name` | 字符串或 `null` | binlog 元数据中的列名；缺失时为 `null` 或生成名称（如 `@0`）。 |
| `mysql_type` | 字符串或 `null` | MySQL 列类型的规范名（如 `LONG`）；镜像未记录该列时为 `null`。 |
| `signedness` | `signed` / `unsigned` / `unknown` 或 `null` | 数值列的符号元数据；非数值列为 `null`。元数据缺失时为 `unknown`，底层按有符号默认解释，需结合表结构核对。 |
| `value` | 对象 | 值，见下表。 |

`value` 的 `type` 取值：

| `value.type` | `value.value` 形态 | 说明 |
| --- | --- | --- |
| `absent` | 无 `value.value` 键 | 该镜像未记录此列。 |
| `null` | 无 `value.value` 键 | SQL NULL。与 `absent` 不同。 |
| `bytes` | 小写十六进制字符串 | 二进制及字符内容；不推断字符集。 |
| `int` | 有符号整数 | 有符号整型。 |
| `uint` | 无符号整数 | 无符号整型。 |
| `float` / `double` | 字符串 | 以字符串保留非有限值。 |
| `date` | `{year, month, day, hour, minute, second, micros}` | 日期/时间分量，含零日期。 |
| `time` | `{negative, days, hours, minutes, seconds, micros}` | 有符号 TIME 分量，可超过 24 小时。 |
| `json` | 任意 JSON | 解码后的完整 JSON 值。 |

## 过滤

所有过滤器以 AND 组合；过滤在解析之后进行，不能绕过解析错误，也不影响解析状态。

- `--events`：保留列出的 `event_type`；不指定则保留所有类型。
- `--table`：只保留匹配的 table map、行事件与部分 JSON 更新事件；Query、XID、GTID 等非表事件会被排除，没有表映射的行事件（`unresolved`）因不携带表名也永不匹配。值在第一个 `.` 处拆分为 `(database, table)` 后按字符串精确比较，不做大小写归一化。
- `--start-position` / `--stop-position`：保留字节偏移 `>= start` 且 `< stop` 的事件（start 含边界，stop 不含）。与 mysqlbinlog 在 stop 位置停止读文件不同，后续事件仍会流经解析器，只是被过滤掉。
- `--start-datetime` / `--stop-datetime`：保留时间戳 `>= start` 且 `<= stop` 的事件（两端均含边界；mysqlbinlog 的 stop-datetime 不含边界，本工具按帮助文本所述为含边界）。时间在参数解析期完成换算，早于窗口或时间戳为零的事件自然不匹配。
- `--include-gtid`：对 GTID 事件的 `payload.gtid` 做精确匹配白名单。UUID 部分归一化为小写，tag 区分大小写且须满足 MySQL tag 规则（1–32 个字符，以字母或下划线开头），GNO 从 1 开始。只保留 GTID 事件本身——与 mysqlbinlog 的 `--include-gtids` 不同，不会保留整个事务。

### 统计模式

`--stats` 用单个 JSON 对象代替事件输出，汇总所有输入处理后仍被保留的事件：

```json
{"files":1,"events_total":4,"bytes_total":127,"transactions":0,"by_type":{"table_map":1,"write_rows":1,"xid":2},"by_table":{"d.t":1},"errors":0}
```

（样例为合成四事件文件——XID、table map、write rows、XID——的真实输出。）计数仅覆盖被保留的事件，因此统计遵循所有其他过滤器。`files` 为处理的输入数；`bytes_total` 为保留事件的 `event_size` 之和；`transactions` 为 GTID payload 事件数（含匿名事务；XID 不计入）；`by_table` 按 `database.table` 统计行变更数（write/update/delete rows 与 `partial_update_rows` 的 before 镜像）；`errors` 为部分解析失败的输入数（进程仍以退出码 3 结束并在标准错误输出逐文件错误摘要）。该模式下 `--format` 被接受但忽略；JSON 对象照常写入标准输出或 `--output` 文件。

## 错误、输入和安全

事件逐个读取，单个事件上限为 64 MiB（可用 `--max-event-size` 调整，硬上限 1 GiB），内存占用与文件大小无关。明文文件头为 `FE 62 69 6E`；加密文件（`FD 62 69 6E`）被明确拒绝，提示通过 MySQL 服务器使用 `mysqlbinlog --read-from-remote-server` 获取明文，但应保护传输及副本。HTTP(S) 下载会先写入自动清理的临时文件，需要足够磁盘空间；下载超过 `--max-download-size`（默认 4 GiB）即中止。HTTPS URL 的重定向不能降级到 HTTP。下载并不会解密数据。

压缩事务 payload（code 40）安全解码：压缩头在底层库解析前完成校验（未知算法是干净的错误）；解压流式进行且有界（声明超过 1 GiB 直接拒绝，解压输出超出声明大小加少量余量即拒绝）；内层事件与外层事件一样做预校验。会改写解析器状态的内层事件（内层 format description、rotate 或嵌套压缩 payload）被拒绝。

事件框架（事件大小、校验和）与解码错误会带文件偏移报告：previous-GTIDs 头部声明的 SID 数与表映射 optional metadata（含 ENUM/SET 变体数）在交给底层解码前做上界预校验，敌意构造的输入返回错误而不是进程崩溃。CRC32 校验和不匹配同样报错。错误按[退出码](#退出码)一节分层处理。

未知事件保留类型码与 `raw_len`；标准 MySQL 5.7+/8.0 binlog 必含的 `previous_gtids` 事件会正常分类。这些情况不一定导致非零退出，不能将成功退出视为所有内容均已解码。旧版本、变体服务端及所有类型尚未全面验证。

服务器开启 `binlog_row_value_options=PARTIAL_JSON` 时，表映射会携带底层库尚不支持的 optional metadata 类型（14/15），文件在第一个表映射处即报错退出；这是底层库的已知边界，而非本工具的预校验引入。

`--output` 不覆盖文件，但 shell 的 `>` 重定向由 shell 控制，可能覆盖目标。

## 与 mysqlbinlog 的差异

- 定位不同：本工具是离线明文 binlog 检查器，不实现 MySQL 服务端协议，也不解密；需要从服务器获取明文时请使用 `mysqlbinlog --read-from-remote-server`。
- 输出面向机器：JSON Lines / CSV 每事件一条记录，行镜像区分缺失列与 SQL NULL；适合管道与脚本处理，不追求 mysqlbinlog 的 SQL 重放输出。
- 功能子集：范围过滤更简单（位置窗口只过滤而非停止读取，时间边界两端均含，GTID 选择按事件精确匹配而非按事务），不生成重放语句，不跟随 Rotate，压缩 payload 内的事务不会解压成可重放 SQL。
- 校验行为：逐事件验证 CRC32 校验和，并对敌意构造的事件头和表映射元数据做 fail-closed 预校验；`partial_update_rows` 只给出 before 镜像。

## 作为 Rust 库使用

在另一个项目的 `Cargo.toml` 中，按实际路径引用源码：

```toml
[dependencies]
binlog-inspect = { path = "../binlog-inspect" }
serde_json = "1"
```

解析器泛型化于任意 `Read` 输入（文件、标准输入、内存缓冲），逐事件读取并以 [`parser::MAX_EVENT_SIZE`](../src/parser.rs)（64 MiB）限制单个事件的内存分配：

```rust,no_run
use binlog_inspect::{event::{EventPayload, EventType}, parser::BinlogParser};
use std::io::Cursor;

// 构造一个最小的合成 binlog：4 字节 magic 加一个 XID 事件
// （19 字节事件头 + 8 字节 XID 事件体）。
fn xid_event(xid: u64) -> Vec<u8> {
    let size = 19u32 + 8;
    let mut event = Vec::new();
    event.extend(1u32.to_le_bytes()); // timestamp
    event.push(16); // XID_EVENT
    event.extend(7u32.to_le_bytes()); // server id
    event.extend(size.to_le_bytes());
    event.extend((4 + size).to_le_bytes()); // log_pos
    event.extend(0u16.to_le_bytes()); // flags
    event.extend(xid.to_le_bytes());
    event
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = b"\xfebin".to_vec();
    bytes.extend(xid_event(42));

    let mut parser = BinlogParser::from_reader(Cursor::new(bytes))?;
    for result in parser.events() {
        let event = result?;
        assert_eq!(event.event_type, EventType::Xid);
        println!("{}", serde_json::to_string(&event)?);
        if let EventPayload::Xid { xid } = event.payload {
            assert_eq!(xid, 42);
        }
    }
    Ok(())
}
```

要点：

- `parser::BinlogParser`：`open`（本地文件，含 magic 与加密头校验）、`from_reader`（任意流）、`with_max_event_size`（调整 64 MiB 默认上限）；`events()` 迭代遇到错误即终止。
- `event` 模块：输出模型，全部类型实现 `Serialize` + `Deserialize`（`CellValue::Bytes` 序列化为小写十六进制字符串，反序列化期望同样形式）；`EventType::as_str` 给出 JSON 中的 snake_case 名称，`from_raw` 完成原始类型码映射。
- `filter::EventFilter`：`kinds: HashSet<EventType>` 与 `tables: HashSet<(String, String)>` 组合过滤，`keep(&event)` 判定。
- `formatter` 模块：`Formatter` trait 直写 `&mut dyn Write` 并返回 `Result<bool, FormatterError>`（表示本事件是否产生输出）；提供 `JsonLinesFormatter`、`TextFormatter`、`CsvFormatter`（`header()` 返回 CSV 表头）。

网络下载仅在 CLI 内实现，不是公开库 API。开发验证命令及真实样本验证范围见[执行与验证](../EXECUTION.md)，设计细节见[设计文档](../DESIGN.md)（均为中文文档）。
