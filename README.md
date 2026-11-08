[![CI](https://github.com/juanmaneo/rea-rs/actions/workflows/ci.yml/badge.svg?branch=trunk)](https://github.com/juanmaneo/rea-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

# rea-rs: Reverse Engineer Anything, in Rust

### A Rust port of [REA](https://github.com/morluto/rea): one local tool for reverse engineering across binaries, applications, and runtime behavior, shared by your terminal and your agent.

**See a feature you like. Understand how it works, down to the binary level.**

`rea-rs` reimplements REA's CLI and MCP workflows in Rust. It keeps upstream's
externally observable contracts — commands, flags, tool names, JSON Schemas,
error contracts, and Evidence shapes — while replacing the Node.js runtime
entirely. Analysis runs locally; results carry the evidence and limitations
behind each conclusion.

> [!IMPORTANT]
> This port is in progress. Only part of upstream's capability set is ported
> today; see [status](#status). The behavioral reference is
> [morluto/rea](https://github.com/morluto/rea), mirrored read-only in this
> repository's `upstream` branch.

[Status](#status) · [Quick start](#quick-start) · [How it works](#how-it-works) · [Design](#design) · [Development](#development) · [Documentation](#documentation)

## Status

Ported end to end:

| Capability | Command | What it returns |
| ---------- | ------- | -------------- |
| ELF notes | `rea inspect-elf-notes PATH` | `PT_NOTE`/`SHT_NOTE` owners and types, GNU build-id and ABI-tag fields, with Evidence |
| Linux kernel modules | `rea inspect-kernel-module PATH` | `.modinfo` entries, `__versions` CRCs, `__ksymtab*` sections, init/exit text, and the appended signature trailer; compressed `.ko` containers are recognized, not decoded |

Shared foundations are in place: the analysis error contract, the Evidence
envelope, canonical JSON digests (RFC 8785, verified against upstream output),
bounded identity-checked file reads, typed input admission, and the CLI
skeleton. The MCP server adapter and the remaining capabilities land in waves;
[PORTING.md](PORTING.md) inventories every upstream area, its target crate,
and its status.

## Quick start

Build from source (Linux or FreeBSD, bring your own Rust toolchain as pinned in
[`rust-toolchain.toml`](rust-toolchain.toml)):

```bash
cargo build --release
```

Inspect the notes of an ELF binary:

```bash
./target/release/rea inspect-elf-notes /absolute/path/to/binary --json
```

The result is Evidence JSON: the findings, their provenance, and the
limitations. Failure results are projected error JSON with exit code 1.

## How it works

You point `rea-rs` at a local target. It inspects the target with the
capability you selected, and returns findings with their evidence: what was
observed, what was derived, what remains unknown. CLI commands and MCP tools
share the same workflows; until the MCP adapter lands, the CLI is the only
entry point.

Static readers parse bytes that were already read; they never run the target.
Capabilities that must execute, inject into, or mutate a target are not ported
yet; when they are, they will run it inside a container, never on the host.

## Design

- **Rust first.** No Node.js anywhere: not as a runtime, not as a helper
  process, not as optional native bindings. Code that must run inside a
  foreign host (Ghidra and JADX scripts, debugger plugins) stays in that host's
  language and stays minimal.
- **Local only.** Analysis runs on your machine. Caller-selected inputs and
  evidence are preserved; transport credentials are redacted.
- **Evidence over answers.** Observations, derivations, inferences, and
  unknowns are distinguished, and provenance survives both adapters.
- **Linux and FreeBSD.** These are the primary platforms for development and
  use. macOS and Windows hosts are a non-goal.
- **Bring your own tools.** Ghidra, IDA, Hopper, debuggers, and the container
  engine are supplied by you. `rea-rs` never installs or upgrades unrelated
  software.
- **Fail closed.** Capabilities with unresolved scope, authority, or
  side-effect questions are not integrated. Targets that cannot run in a
  matching container are refused, not guessed at.
- **Containment.** Target execution will run in a container built from a
  Containerfile kept in this repository: network off by default, least
  privilege, the target mounted read-only, root allowed inside the container
  but never on the host. No execution capability is ported yet.

## Development

The workspace uses the cargo xtask pattern:

```bash
cargo xtask check      # type-check every workspace target
cargo xtask fmt        # format (--check to verify only)
cargo xtask clippy     # lints with -D warnings
cargo xtask test       # run tests (-p CRATE for one crate)
cargo xtask coverage   # tests under cargo-llvm-cov (bring your own)
cargo xtask doc        # build docs with -D warnings
cargo xtask ci         # the full gate
```

Crate dependencies flow inward: domain semantics and contracts, provider
adapters, shared application workflows, then the CLI and MCP adapters. See
[docs/architecture.mermaid](docs/architecture.mermaid) for the current
composition.

Contributions follow [AGENTS.md](AGENTS.md): port by capability with its tests,
preserve upstream's external contracts, use Conventional Commit subjects, and
run `cargo xtask ci` before declaring a change done. AI-assisted contributions
are welcome; a human reviews and owns the final diff.

## Documentation

| Document | Contents |
| -------- | -------- |
| [PORTING.md](PORTING.md) | The porting inventory: every upstream area, its target crate, status, wave order, and the per-capability checklist |
| [LEARNING.md](LEARNING.md) | Maintainer decisions and their consequences |
| [AGENTS.md](AGENTS.md) | Repository rules for agents and contributors |
| [docs/architecture.mermaid](docs/architecture.mermaid) | The crate composition diagram |
| [upstream REA docs](https://github.com/morluto/rea/tree/main/docs) | The behavioral reference for each capability |

## License

MIT, like upstream REA. See [LICENSE](LICENSE), which keeps the upstream
copyright notice alongside this port's.
