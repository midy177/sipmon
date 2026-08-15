# sipmon

SIP/RTP 信令与媒体质量监控工具。独立 Rust 可执行程序，旁路部署在镜像口/抓包机，
**无需依赖运行中的 PBX**。输入可以是实时抓包、pcap 文件、stdin 流或自身录制的事件日志；
输出为实时 TUI 监控与可导出的分析结果（SQLite / JSONL）。

## 特性

- **多输入源**：实时网卡（libpcap + BPF）、离线 pcap/pcapng、stdin 的 `tcpdump -w -` 流、事件日志回放
- **三模式**：`live` 交互监控 / `record` 无头录制（可 `-d` daemon 化）/ `replay` 回放
- **SIP 关联**：Call-ID 呼叫状态机、事务（branch+method）、Call-ID / 号码 / IP / SSRC 索引、SIP-over-TCP 重组
- **媒体质量**：RFC3550 jitter/loss（64 包重排窗）、RTCP RR LSR/DLSR 的 RTT、单向延迟估算、E-model MOS
- **TURN 识别**：自动学习 TURN 服务器，标注 `turn-client` / `turn-peer` 中继腿
- **诊断**：Contact 可达性、Record-Route、SDP/RTP 一致性、单向媒体、TURN 分配/刷新等 20+ 条规则
- **TUI**：Overview / Search / Call Detail（左右分栏）/ Heatmap / Streams / EventLog
- **导出**：退出时或 `export` 子命令导出 SQLite / JSONL；`query` 按 Call-ID 脚本化查 flow

## 构建

```sh
# GNU 动态链接（开发）
cargo build

# 静态 musl release（部署到无依赖的目标机）
# 需要先准备 musl 版的 libpcap（见下），然后：
LIBPCAP_LIBDIR=/path/to/musl/libpcap/lib LIBPCAP_VER=1.10.4 \
  cargo build --release --target x86_64-unknown-linux-musl
# 产物：target/x86_64-unknown-linux-musl/release/sipmon（statically linked）

# 交叉编译 libpcap（musl）
#   wget https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz
#   tar xf libpcap-1.10.4.tar.gz && cd libpcap-1.10.4
#   CC=musl-gcc ./configure --host=x86_64-unknown-linux-musl \
#     --disable-shared --enable-static --prefix=$PWD/install
#   make -j && make install
```

## 快速开始

```sh
# 实时监控（所有网卡，进 TUI）
sipmon live -i any

# 仅看 SIP 5060 端口
sipmon live -i eth0 -f "udp port 5060"

# 后台持续录制到事件日志（daemon），之后可回放/查询/导出
sipmon record -i any -w cap.evlog -d --pidfile /run/sipmon.pid --logfile /var/log/sipmon.log

# 回放历史录制（进 TUI）
sipmon replay -l cap.evlog

# 离线分析 pcap
sipmon file -r capture.pcap

# 默认输入：直接给文件名即可（无需子命令）
#   *.pcap / *.pcapng  → 等价于 `file -r`
#   *.evlog            → 等价于 `replay -l`
sipmon capture.pcap
sipmon cap.evlog

# 从 tcpdump 流读入（实时转发）
tcpdump -i eth0 -w - | sipmon -
```

## 命令详解

| 命令 | 说明 |
|---|---|
| `(无)` | 默认模式：位置参数 `FILE` 直接按扩展名分派——`.pcap/.pcapng` 走 `file -r`，`.evlog` 走 `replay -l`；`--no-tui` 可无头输出 |
| `live` | 实时抓包 + TUI。`-i any` 捕获全部网卡，`-f` BPF 过滤，`--no-media` 关闭 RTP/RTCP 分析，`-w` 可选同时落事件日志 |
| `record` | 无头录制：live 抓包 → 事件日志（`-w` 必填）。`-d` daemon 化、`--pidfile` 写 PID、`--logfile` 重定向 stderr。收到 SIGTERM/SIGINT 时优雅 flush 落盘 |
| `-` | 从 stdin 读 pcap 字节流（`tcpdump -w -` 管道） |
| `file` | 离线 pcap/pcapng。`--rate 1x` 按实时倍速回放，`--no-tui` 无头输出，`--print-events` 打印结构化事件 |
| `replay` | 回放事件日志（TUI / `--no-tui`） |
| `query` | 无 TUI，按 Call-ID 从事件日志导出 flow + 流统计 + RTT + 诊断（脚本友好） |
| `export` | 把事件日志重建成快照并导出 SQLite/JSONL，`--from/--to` 时间过滤（Unix 秒） |

### 通用选项

```
--dry-run            纯内存分析，不写任何文件（record 例外：记录总是落盘）
--max-calls N        内存中最多保留呼叫数（默认 100000，超限先淘汰最老已终止的）
--max-streams N      RTP 流 ring 上限（默认 50000）
--max-diagnostics N  诊断 ring 上限（默认 50000）
--diag-level X       info|warn|critical（默认 warn）
--turn-servers IP,…  TURN 服务器 IP 列表（也支持自动学习）
--raw-truncate N     存储的原始 SIP 报文截断到 N 字节
--bucket 15m|1h|1d   Heatmap 桶粒度（默认 15m）
-w/--evlog PATH      写入二进制事件日志
--export-jsonl PATH  退出时导出 JSONL
--export-sqlite PATH 退出时导出 SQLite
```

## TUI 使用指南

### 页面

| 页 | 快捷键 | 内容 |
|---|---|---|
| **Overview** | `1` | 汇总卡（活跃/完成/失败、avg PDD/jitter/loss、ASR）+ 呼叫表 |
| **Search** | `2` 或 `/` | 搜 Call-ID / From / To / 远端 IP / SSRC，`Enter` 进呼叫 |
| **Call Detail** | `3` | 进入通话后的详情（见下） |
| **Heatmap** | `4` | 时间 × 远端 IP 的 ASR 网格，`b` 切桶粒度 |
| **Streams** | `5` | 每 RTP 流实时统计表（SSRC/Codec/丢包/jitter/RTT/MOS） |
| **Event Log** | `6` | 诊断与呼叫状态变化事件 |

### 顶栏

3 行：**第 1 行** 源/时长/pps/包数/呼叫数/诊断数/暂停态/状态消息；**第 2 行** 全局快捷键；
**第 3 行** 当前页专用快捷键。

### 全局按键

```
Tab / Shift-Tab   切页（Call Detail 内为切右栏子视图）
1-6               直达对应页
/                 搜索（并进入 Search 编辑态）
Space             暂停 / 恢复
e                 导出当前快照为 JSONL（sipmon-export-*.jsonl）
b                 切 Heatmap 桶粒度（15m→1h→1d）
q / Esc / Ctrl-C  退出
```

### Call Detail 左右分栏

进入通话后固定左右分栏：**左 = Flow 消息表**，**右 = 选中消息/通话详情**。
Overview/Search 中 `Enter` 直接打开当前选中呼叫（未选中时默认打开第一行）。

```
┌ 顶栏 ─────────────────────────────────────────────┐
│ Call <id> (from → to) [state]                     │
├───────────────┬───────────────────────────────────┤
│ 左: Flow 列表   │ 右: [Raw|Network|Diagnostics]   │
│ 消息时序表     │   Raw       = 选中消息完整报文     │
│ (可上下选择)   │   Network   = 通话级媒体流统计     │
│               │   Diagnostics= 通话级诊断          │
└───────────────┴───────────────────────────────────┘
```

Call Detail 内按键：

```
↑ / ↓       在左侧 Flow 列表中选消息（Raw 随之联动）
Tab         切换右侧子视图 Raw → Network → Diagnostics
PgUp/PgDn   Raw 长文本滚动
← / Esc     返回列表（Overview）
```

## 事件日志格式

私有二进制 append-only 格式（`EvlogWriter`/`EvlogReader`）。文件头含 magic `SMON`、
版本与时区；记录为 `ts_delta | ev_type | len | payload`。事件类型：

```
1 SipMsgEvt        { flow, call_id, cseq, branch, method|status, from/to_tag, raw[≤truncate] }
2 TxnEvt           { call_id, branch, method, response_code, delay_ms }
3 CallEvt          { call_id, kind: Setup|Update|Teardown, state, 时间戳, cause }
4 StreamSnapEvt    { call_id, ssrc, flow, codec, packets, lost, jitter_ms, ts_window_us }  // 每 5s
5 RtcpRttEvt       { call_id, ssrc, ts_us, rtt_ms, oneway_ms }
6 HealthBucketEvt  { bucket_us, dim_key, metric_set }
7 ErrorEvt         { ts, kind, msg }
8 DiagEvt          { ts, call_id, severity, code, message }
```

**不存原始 RTP 载荷**，只存重建分析所需摘要 + 截断后的 SIP 原始报文（`--raw-truncate` 控制）。
`record` 默认持续落盘；`live` 需显式 `-w`。

## 诊断码

| 代码 | 含义 |
|---|---|
| `CONTACT_UNREACHABLE` | Contact 地址不可达（环路/黑洞） |
| `CONTACT_PRIVATE_NAT` | Contact 使用私网地址，可能需 NAT/中继 |
| `CONTACT_MCAST` | Contact 为组播地址 |
| `RR_NOT_HONORED` / `RR_DEPTH_MISMATCH` | Record-Route 未遵循 / 深度不一致 |
| `SDP_HOLD` | SDP 携带 hold（`sendonly`/`inactive`） |
| `RTP_PT_MISMATCH` / `RTP_PT_CHANGED` / `RTP_FLOW_UNEXPECTED` | 载荷类型不符 / 中途变更 / RTP 流向与 SDP 不符 |
| `ONE_WAY_MEDIA` | 单向媒体（只收不发） |
| `TURN_ALLOC_OK` / `TURN_ALLOC_FAILED` / `TURN_REFRESH_FAILED` | TURN 分配成功 / 失败 / 刷新失败 |
| `TURN_RELAY_MEDIA` / `TURN_CHANNEL_MEDIA` / `TURN_SEND_IND_MEDIA` | 媒体经 TURN Relay / ChannelData / Send-Ind 中继 |
| `TURN_LEG_IMBALANCE` | TURN 两腿包量失衡（疑似单向） |

## 指标口径

- **RTT**：RTCP RR 的 `RTT = arrival_NTP − LSR − DLSR`
- **单向延迟**：RTCP SR 的 NTP↔RTP 映射（双向可见时）；否则用 RTP 到达间隔间接估算（标注"估算"）
- **jitter/loss**：RFC3550，64 包重排窗
- **MOS**：简化 E-model（G.107）：`R = 93.2 − Id − Ie`，标注"估算"

## 限制

- TLS/SRTP 加密载荷不可解析，需在解密点抓包
- 单向旁路下的绝对单向延迟为估算值；主指标用 RTCP RTT
- 无网卡权限时需以 root / 高权限运行（同 tcpdump）

## 测试

```sh
cargo test                       # 单测 + 集成测试（pcap fixture）
cargo test --test cli_integration
```
