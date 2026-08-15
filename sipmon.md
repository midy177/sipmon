# sipmon 详细开发方案

SIP/RTP 信令与媒体质量监控工具。独立 Rust 可执行，旁路部署在镜像口/抓包机，**无需依赖运行中的 PBX**。

输入 = 实时抓包（libpcap）/ pcap 文件 / stdin 的 `tcpdump -w -` 流 / 自身事件日志回放 / **record 录制的事件日志**；输出 = 实时 TUI 监控 + 可导出的分析结果（事件日志 → SQLite/JSONL）。

```
[镜像口网卡] ──┐
[*.pcap]    ──┤──▶ Capture ─▶ Decode ─▶ Parse ─▶ Correlate ─▶ Analyze ─▶ In-Memory ─▶ TUI
[tcpdump -w-] ─┘                       (L2/L3/L4)   (SIP)   (Call+RTP)   (指标)   (AppState)   │
[sipmon record] ─▶ evlog ─▶ replay ─┘                                                           ▼
                                                                                    事件日志 ─▶ SQLite/JSONL 导出
```

## 技术决策

- **语言**: Rust（复用 `rsipstack` SIP 解析、vendor `rustpbx-sipflow` 的 RTP 统计）
- **实时抓包**: libpcap 绑定（`pcap` crate + BPF 过滤），权限需求同 tcpdump；离线 pcap 文件与 stdin 流同样支持
- **记录格式**: 新建独立事件日志（二进制 append-only，不含原始 RTP 载荷）
- **集成方式**: 独立可执行，不依赖运行中的 PBX
- **存储**: 内存 + 导出（热数据在内存，定期/退出/信号导出归档）
- **TUI 范围**: 实时监控 + 离线分析
- **可靠性指标**: 全量（建立时延/PDD、RTP jitter/loss/延迟、挂断原因，按 IP×时段聚合成失败率 + MOS 估算 heatmap）
- **Heatmap 维度**: 时间×远端 IP 与 时间×本地端点 都支持，页面可切换
- **延迟测量**: RTCP RR 的 LSR/DLSR 算 RTT（双向可见）；单向时用 RTP 到达间隔间接估计（标注"估算"）

## 一、项目结构

```
sipmon/
├── Cargo.toml
└── src/
├── main.rs              clap CLI / 子命令 / tokio runtime
├── config.rs            阈值/桶粒度/过滤/存储路径
├── error.rs
├── model/               纯数据结构（无逻辑）
│   ├── packet.rs        CapturedPacket, Flow5Tuple
│   ├── sip.rs           SipMsg, SipTransaction, Call, Leg, CallState, HangupCause
│   ├── media.rs         RtpStream, RtcpReport, StreamSummary
│   └── stats.rs         HealthBucket, MetricSet
├── capture/             输入源（统一 CaptureSource trait）
│   ├── live.rs          LivePcap  (pcap crate + BPF)
│   ├── file.rs          PcapFile  (pcap-file crate, pcap/pcapng)
│   ├── stdin.rs         StdinPcap (tcpdump -w -)
│   └── replay.rs        EventReplay (读自身事件日志重分析)
├── decode/              L2→L7
│   ├── frame.rs         etherparse: Eth/VLAN/SLL/IP/TCP/UDP
│   ├── sip.rs           SIP 分类 + rsipstack 解析
│   ├── rtp.rs           RTP 头解析
│   ├── rtcp.rs          RTCP SR/RR (LSR/DLSR/loss fract/RR)
│   └── tcp_reasm.rs     SIP-over-TCP 流重组（Content-Length 分帧）
├── correlate/
│   ├── transaction.rs   branch+method 事务关联
│   ├── call.rs          Call-ID 状态机
│   └── stream.rs        5-tuple+ssrc → call+leg 归属
├── analyze/
│   ├── media_stats.rs   vendor 自 rustpbx-sipflow: RFC3550 jitter/loss
│   ├── rtcp_rtt.rs      LSR/DLSR RTT + SR NTP↔RTP 单向延迟
│   ├── mos.rs           E-model G.107 MOS 估算
│   └── metrics.rs       PDD/setup delay/hangup/reliability
├── store/
│   ├── registry.rs      活动呼叫注册表 + Call-ID/号码/IP/SSRC 索引
│   ├── heatmap.rs       聚合桶（time×IP / time×endpoint）
│   └── evlog.rs         事件日志二进制读写
├── export/
│   ├── sqlite.rs        rusqlite 导出
│   └── jsonl.rs
└── ui/                  ratatui TUI
    ├── overview.rs      汇总卡片 + 呼叫表
    ├── search.rs        sngrep 风格 Call-ID/号码/IP/SSRC 查询
    ├── call_detail.rs   flow / raw 报文 / 网络统计 三子视图
    ├── heatmap.rs
    ├── streams.rs
    └── eventlog.rs
```

## 二、核心数据结构

```rust
// model/packet.rs
struct Flow5Tuple { proto: Proto, src: SocketAddr, dst: SocketAddr }   // 枚举 key
struct CapturedPacket { ts_us: u64, flow: Flow5Tuple, payload: Bytes }

// model/sip.rs
enum CallState { Dialing, Ringing, Active, Completed, Failed, Canceled }
struct HangupCause { code: Option<u32>, reason: Option<String> }       // Q.850/Reason 头
struct Leg { tag_from, tag_to, branch, remote: SocketAddr, local: SocketAddr, direction }
struct SipMsg { ts_us, flow, is_request, method: Option<Method>,
                status: Option<u16>, call_id, cseq, branch, from_tag, to_tag,
                raw: Bytes /* 按 --raw-truncate 截断 */ }
struct Call {
    call_id, legs: Vec<Leg>, state: CallState,
    invite_ts: Option<u64>, trying_ts, ringing_ts, answer_ts, bye_ts: Option<u64>,
    pdd_ms: Option<u32>, setup_ms: Option<u32>,
    hangup: HangupCause, outcome: Outcome,
    media: Vec<StreamSummary>,
    pkts_sip: u64, pkts_rtp: u64, pkts_rtcp: u64, bytes: u64,
}

// model/media.rs
struct RtpStream { flow, ssrc: u32, pt: u8, codec: String, clock_rate: u32,
                   acc: MediaStatsAccumulator /* vendor */ }
struct RtcpRtt { ts_us, ssrc, rtt_ms: f64 }
struct StreamSummary { ssrc, codec, packets, lost, loss_pct, jitter_ms,
                       rtt_min/rtt_avg/rtt_max_ms: Option<f64>, oneway_ms: Option<f64>, mos: Option<f64> }
```

## 三、事件日志格式（自有二进制）

Append-only，文件头 + 记录流。**不存原始 RTP 载荷**，只存重建分析所需的摘要。

```
FileHeader:  magic "SMON"(4) | version u16 | flags u16 | tz_offset i32
Record:      ts_delta varint | ev_type u8 | len varint | payload[len]
事件类型 ev_type:
  1 SipMsgEvt       { flow, call_id, cseq, branch, method|status, from/to_tag, raw[<=truncate] }
  2 TxnEvt          { call_id, branch, method, response_code, delay_ms }
  3 CallEvt         { call_id, type: Setup|Update|Teardown, state, timestamps..., cause }
  4 StreamSnapEvt   { call_id, ssrc, flow, codec, packets, lost, jitter_ms, ts_window_us }  // 每 5s
  5 RtcpRttEvt      { call_id, ssrc, ts_us, rtt_ms, oneway_ms }
  6 HealthBucketEvt { bucket_us, dim_key, metric_set }
  7 ErrorEvt        { ts, kind, msg }
```

写入：后台单线程从有界 channel 消费，批量 flush。读取：`replay.rs` 顺序解析喂回 pipeline。

事件日志保留 `SipMsgEvt` 原始报文字节（默认开，可 `--raw-truncate` 截断），**历史呼叫可事后按 Call-ID 查出完整 flow**。

## 四、关键算法

**RTP/RTCP 分类**：UDP 载荷首字节 `version=2`；`PT = payload[1]&0x7f`，PT∈{200..207} 为 RTCP（SR/RR/SDES/BYE/APP/RTPFB/PSFB/XR），否则 RTP。TCP 上 SIP 按 Content-Length 重组。

**RTT（RTCP RR）**：`RTT = arrival_NTP − LSR − DLSR`（LSR/DLSR 各 32bit，NTP 中 32 位）。
**单向延迟（RTCP SR）**：SR 含 NTP(64)+RTP_ts(32) 映射；双向可见时把对端 RTP_ts 投影到本端到达 NTP，减去发送方 NTP 得单向延迟。仅单向时退化用 RTP 到达间隔相对抖动间接估计（标注"间接"）。

**jitter/loss**：直接 vendor `MediaStatsAccumulator`（RFC3550，带 64 包重排窗、`j += (D−j)/16`）。

**MOS（简化 E-model, G.107）**：
`R = 93.2 − Id(延迟+jitter) − Ie(编解码, 丢包率)`
`MOS = 1 + 0.035R + 7e-6·R·(R−60)·(100−R)`（R<100；R≥100 取 4.5）。标注"估算"。

**Heatmap 聚合**：二维 map `(bucket_us, key)`，key=远端 IP（可 /24 聚合）或本地端点；每桶累加 calls/answered/failed/pdd/jitter/loss/rtt/mos，导出 ASR、setup_fail_rate、各均值。桶粒度 15min/1h/1d 可切。

## 五、TUI 设计（ratatui + crossterm）

顶栏：源、时长、pps、包数、丢包数、暂停态。

| 页 | 内容 | sngrep 对应 |
|---|---|---|
| **Overview** | 汇总卡（活跃/完成/失败、avg PDD/jitter/loss、ASR）+ 呼叫表 | call list |
| **Search** | `/` 搜 Call-ID / From / To / 远端 IP / SSRC，模糊匹配，结果列表 `Enter` 进呼叫 | call filter |
| **Call Detail** | 固定左右分栏：左 **Flow** A→B 时序消息表（上下选消息），右子视图 `Tab` 切：① **Raw** 选中消息完整 headers+SDP ② **Network** 5元组+SIP/RTP/RTCP 包计+每流统计+RTT 曲线 ③ **Diagnostics** 通话级诊断 | flow / message / — |
| **Heatmap** | 网格 time×远端IP（`e` 切 time×本地端点）；选格→桶内呼叫列表 | — |
| **Streams** | 每 RTP 流实时统计表 | — |
| **EventLog** | 自身事件日志尾部 | — |

按键：`Tab` 切页（Call Detail 内为切右栏子视图）/ `1-6` 直达 / `/` 搜索 / `f` BPF 过滤 / `Space` 暂停 / `e` 导出 / `b` 切桶粒度 / `q` 退出。

## 六、CLI 接口

```
sipmon live   -i any [-f bpf] [--no-media] [-w log]        # 实时抓包 + TUI（-i any 捕获全部网卡；可选同时落 evlog）
sipmon record -i any [-f bpf] [--no-media] -w log [-d] [--pidfile p] [--logfile l]
                                                           # 无头录制：live 抓包 → 二进制事件日志（-w）
                                                           # -d 后台 daemon 化；SIGTERM/SIGINT 优雅落盘退出
sipmon -                                          # 从 stdin 读 pcap 流（tcpdump -w -）
sipmon file   -r cap.pcap [--pcapng] [--rate 1x]       # 离线 pcap 分析 + TUI（可调速）
sipmon replay -l sipmon.evlog                         # 回放事件日志 + TUI
sipmon query  -l sipmon.evlog -c <callid>             # 无 TUI，按 Call-ID 查 flow+stats（脚本友好）
sipmon export -l sipmon.evlog --sqlite out.db|--jsonl out.jsonl [--from --to]
sipmon cap.pcap | cap.evlog                           # 默认模式：无子命令，按扩展名分派到 file/replay
通用: --store-raw-messages --raw-truncate 1024 --bucket 15m --ring-hours 24 --export-jsonl/--export-sqlite --dry-run
```

模式矩阵：

| 模式 | 输入 | 输出 | 说明 |
|---|---|---|---|
| `(默认 FILE)` | pcap/pcapng 或 evlog | 同 file/replay | 无子命令时按扩展名分派：`*.pcap/pcapng` → `file -r`，`*.evlog` → `replay -l` |
| `live` | 网卡/stdin/pcap | TUI +（可选）evlog | 交互监控 |
| `record` | 网卡 | evlog（必填） | 无头录制，`-d` 可 daemon 化，适合 7×24 持续采集 |
| `replay` | evlog | TUI / 无 TUI JSON | 回放分析历史录制 |

## 七、依赖清单

| 用途 | crate | 版本 |
|---|---|---|
| TUI | ratatui + crossterm | 0.30 / 0.28 |
| 实时抓包 | pcap | 2.4 |
| 离线 pcap/pcapng | pcap-file | 3.0 |
| L2-L4 解码 | etherparse | 0.16 |
| SIP 解析 | rsipstack（path 依赖） | 0.5.24 |
| RTP/RTCP/jitter/loss | **vendor** media_stats.rs | — |
| SQLite 导出 | rusqlite（bundled feature） | 0.32 |
| 运行时 | tokio（full） | 1.52 |
| 其它 | chrono, serde, serde_json, bytes, clap, anyhow, tracing, tracing-subscriber, dashmap | — |

## 八、里程碑（每个都有可验证产物）

**M0 — 数据通路（无 TUI）**
- 4 个输入源 + frame 解码 + SIP 解析（UDP）+ RTP/RTCP 分类 + 事件日志落盘
- 验证：`sipmon file -r sample.pcap --print-events` 输出结构化 SIP 消息；`sipmon - < <(tcpdump -r x.pcap -w -)` 通

**M1 — 关联与指标**
- 事务/呼叫/流关联 + PDD/setup/hangup + jitter/loss + RTCP RTT + MOS + 内存 AppState + Heatmap 桶
- 验证：单测覆盖状态机、RTT、loss 重排窗、MOS；对真实呼叫 pcap 输出每呼叫指标 JSON

**M2 — TUI（实时+分析）**
- Overview / Search(sngrep) / Call Detail(Flow+Raw+Network) / Heatmap / Streams / EventLog
- 验证：live 与 file 两种源下 TUI 全页可用；Call-ID 搜索命中历史呼叫并显示 flow

**M3 — 导出与回放**
- sqlite/jsonl 导出 + `query` 子命令 + `replay` 从事件日志重分析 + 离线 pcap 调速
- 验证：导出后 SQL 查询能复现 heatmap；replay 重建与实时一致

**M4 — 打磨**
- BPF 交互过滤、/24 子网聚合、报告导出（HTML/CSV）、SIP-over-TCP 流重组完善、文档

## 九、测试策略

- `tests/pcap_fixtures/`：构造含 INVITE→200→RTP→BYE 的 pcap（可用现有 sipflow bench 数据），覆盖 loss/重排/RTCP
- 单测：状态机、RTP 头/RTCP 解析、jitter/loss 算法、RTT、MOS、事件日志 round-trip
- 集成：`file`/`stdin`/`replay` 三路输入对同一 pcap 产出一致指标
- 基准：高 pps 下 ring buffer 不丢（参考 sipflow 的 recv-buffer/多接收任务模式）

## 十、风险与应对

| 风险 | 应对 |
|---|---|
| TLS/SRTP 不可解析 | v1 不做；文档标注需在解密点抓包 |
| 高峰内存 | 有界 ring + 桶降采样 + 定时归档（复用 sipflow 批量 flush 思路） |
| 单向旁路绝对延迟不准 | 主指标用 RTCP RTT；单向仅作"估算"标注 |
| SIP-over-TCP 重组复杂 | M0 先 UDP；M4 补 TCP（Content-Length 分帧） |
| rsipstack 拉入重依赖 | 实测仅解析层，无网络栈；如过重则 vendor 解析子集 |
