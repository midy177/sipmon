# sipmon — 被动式 SIP/RTP 信令与媒体质量监控(纯 Rust 单二进制)

> 面向 rustcc 读者:这篇主要介绍**产品功能**。实现与性能优化的长文见文末链接。

## 一句话

`sipmon` 是一个**被动式**的 SIP/RTP 信令与语音质量监控工具:部署在镜像口/分流口的抓包机上,旁路监听,**不依赖运行中的 PBX**,一边抓包一边在实时 TUI 里展示每一通电话的质量、每个 IP 的丢包情况,并支持离线 pcap 分析、历史录制回放与 JSONL 导出。

- 仓库:`https://github.com/miuda-ai/sipmon`
- crates.io:`sipmon`(`cargo install sipmon`)
- 单二进制,纯静态 musl 构建,无运行时依赖、无外部数据库

## 主要功能

### 输入 / 运行方式(一个工具,四种来源)
- **实时抓包**:libpcap,支持 BPF 过滤(`-f "udp port 5060"`),`-i any` 全接口
- **离线分析**:pcap / pcapng 文件,支持 `--rate` 倍速回放
- **stdin 管道**:`tcpdump -w - | sipmon -`,直接把 tcpdump 的流喂进来
- **录制回放**:`record` 模式把实时抓包写成二进制事件日志(evlog),支持 `-d` 守护化;之后 `replay` 回放、`query` 按 Call-ID 取流、`export` 导出 JSONL
- 三种模式:`live`(实时 TUI)/ `record`(无头录制)/ `replay`(回放)

### 呼叫关联
- 基于 Call-ID 的呼叫状态机,事务按 `branch+method` 关联
- Call-ID / 号码 / IP / SSRC 多重索引,`query` 一条命令拉出整通电话的流程与统计
- SIP-over-TCP 重组,长消息不丢

### 媒体质量
- RFC3550 抖动 / 丢包(64 包重排窗口)
- RTCP RR LSR/DLSR RTT 与单向时延估计
- 简化 E-model(ITU-T G.107)MOS 评分
- PDD / setup / ring 时序、180 vs 183 早期媒体、挂机方判定(caller/callee BYE、CANCEL、拒绝码)

### 网络层面
- **TURN 自动学习**:识别 TURN 中继腿(`turn-client` / `turn-peer`),看清媒体是否绕路
- **按 IP 的进出方向(TX/RX)独立统计**:每个 IP 分别给出发送/接收的包数、字节、丢包率,不再合并
- 丢包率时间窗(1s … 1h)与 IP 丢包热力图,一眼定位"哪个 IP 在哪个时间段丢包"

### 诊断与排查
- 20+ 条内置诊断规则:Contact 可达性、Record-Route、SDP/RTP 一致性、单向媒体、TURN allocation/refresh 等,按 warn / critical 分级
- TUI 的 Call Detail 固定四栏布局:消息流 + 诊断 / 原始报文 + 媒体流统计,随时核对

### TUI(7 个页面,底部 1-7 tab 条)
Overview(呼叫总览)· Search(sngrep 式搜索)· Call Detail(四栏详情)· Heatmap(IP 丢包热图)· Streams(逐流统计)· Event Log(诊断事件流)· IP Stats(按 IP 的 TX/RX 统计 + 下钻)

## 快速上手

```sh
# 实时监控(所有网卡,打开 TUI)
sipmon live -i any

# 仅 5060 端口
sipmon live -i eth0 -f "udp port 5060"

# 分析历史 pcap
sipmon file -r capture.pcap

# 后台录制到事件日志(守护化)
sipmon record -i any -w cap.evlog -d --pidfile /run/sipmon.pid

# 回放录制结果
sipmon replay -l cap.evlog

# 或直接丢文件,按扩展名自动分发(.pcap/.pcapng/.evlog/.jsonl)
sipmon capture.pcap
```

## 实现与性能

双线程模型(主线程 TUI + 工作线程流水线)、快照 100ms 增量发布、全量有界内存(环形淘汰)+ 每 IP 两级时间桶(1s×600、1m×60)做 O(窗口桶数)的丢包窗口计算、O(1) 的"五元组→呼叫"哈希关联、纯静态单二进制部署。长文见:

- 知乎版(实现与性能优化):仓库 `docs/zhihu.md`

## 结尾

开源 MIT,欢迎 star、issue 和 PR(尤其是新的诊断规则)。如果你在维护 VoIP / 联络中心,这个工具或许能帮你把"抓包-分析"从命令行苦活变成实时可视化的过程。
