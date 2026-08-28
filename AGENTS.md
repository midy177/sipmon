# Repository Guidelines

## Project Structure & Module Organization

`sipmon` is a Rust 2024 CLI/TUI for passive SIP/RTP monitoring. The binary entry point is `src/main.rs`. Core modules live under `src/`: `capture/` handles live, file, stdin, and replay inputs; `decode/` parses packet protocols; `correlate/` links SIP, RTP, RTCP, and TURN data; `analyze/` computes media metrics; `store/` owns snapshots, event logs, and stats; `ui/` contains Ratatui screens. Integration tests are in `tests/`. README images such as `call_detail.png`, `sip_stats.png`, and `rtp_stats.png` sit at the repository root.

## Build, Test, and Development Commands

- `cargo build`: build the local debug binary.
- `cargo run -- file -r capture.pcap --no-tui`: run offline pcap analysis without the TUI.
- `cargo test`: run unit and integration tests.
- `cargo fmt --all -- --check`: verify Rust formatting.
- `cargo clippy --all-targets --all-features -- -D warnings`: catch lint issues before review.
- `make help`: list release and cross-compile targets.
- `make musl-x86_64` / `make musl-aarch64`: build static Linux release binaries through `cargo zigbuild`.

## Coding Style & Naming Conventions

Use standard `rustfmt` formatting with four-space indentation. Keep modules aligned with existing boundaries: packet parsing in `decode`, event persistence in `store::evlog`, terminal presentation in `ui`, and metrics in `analyze`. Use descriptive snake_case for functions, variables, and modules; use UpperCamelCase for structs, enums, and traits. Keep hot-path code allocation-conscious, matching existing use of compact data structures and `rustc-hash`.

## Testing Guidelines

Add focused unit tests near the module under test and CLI coverage in `tests/*.rs`. Test names should describe observable behavior, for example `default_positional_pcap_mode` or `evlog_roundtrip_and_query`. CLI tests should invoke the compiled `sipmon` binary and assert on exit status plus stable stdout or JSON fields. Run `cargo test` before submitting changes; use narrower commands such as `cargo test turn` while iterating.

## Commit & Pull Request Guidelines

Recent history uses concise scoped subjects such as `perf: ...`, `chore: ...`, and `bump 0.1.17: ...`. Keep the first line specific and include the subsystem or outcome when useful. Pull requests should explain user-visible changes, affected commands or modes, linked issues, and screenshots for TUI-visible changes. Note skipped tests or fixture requirements explicitly.

## Security & Configuration Tips

Do not commit captures, event logs, or SIP payloads containing private data. Prefer `--raw-truncate`, `--dry-run`, and privacy masking when reproducing issues. Keep release artifacts under `target/`, and avoid checking in cross-build cache output.
