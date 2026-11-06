# Repository Guidelines

`rea-rs` is a Rust port of [REA](https://github.com/morluto/rea), not just a fork. Write as much as possible in Rust. Upstream REA (TypeScript/Node.js) is the behavioral reference, not the implementation template. Maintainer decisions and agent rules are recorded in [LEARNING.md](LEARNING.md).

## Repository and Upstream Reference

- `trunk` is the default branch. All Rust port work lands here.
- `upstream` mirrors `morluto/rea` `main` and is read-only. Never commit to it, rebase it, or merge `trunk` into it.
- Upstream docs referenced below exist only on `upstream`. Read them locally with `git show upstream:PATH` (for example `git show upstream:docs/tool-design.md`) or `git worktree add`. Do not copy them wholesale into `trunk`; port only what the Rust code needs, adapted.
- Agents must not run remote git operations (`push`, `fetch`, `pull`, `clone`, `ls-remote`, or anything else that contacts or changes a remote). The maintainer handles syncing.

## Product and Authority

REA is a local-only reverse-engineering tool with shared CLI/MCP workflows. Distinguish observations, derivations, inferences, and unknowns; preserve Evidence provenance and session semantics through both adapters.

Follow upstream's contribution scope and fail-closed integration rule (`upstream:CONTRIBUTING.md`, "Contribution scope"). Do not integrate capabilities while material scope, authority, side-effect, or required verification questions remain unresolved. For new providers or capabilities involving target execution, injection, mutation, or protection recovery, get the maintainer's scope decision before substantial implementation. Early proposals, small exploratory prototypes, and drafts that help resolve questions are welcome; they do not authorize integration.

Ghidra uses ephemeral databases without modifying executable bytes or controlling a GUI; Windows Ghidra P0 has no mutation authority. IDA analysis is read-only; never save or close an attached GUI database.

Configuration changes must be additive and idempotent, with backups. Installers must not install or upgrade unrelated software, including Homebrew, Rust toolchains, Node.js, Java, or Ghidra. Ghidra and IDA are bring-your-own. `rea setup` must show its planned changes and require approval before writing files or installing Hopper.

Preserve caller-selected inputs and local evidence, including output, URLs, paths, digests, and metadata. Redact transport authentication credentials and explicitly marked sensitive values; do not infer secrecy from names or text patterns. Do not persist the ambient environment merely because a child inherits it.

## Porting from Upstream

- Port by capability, not by file. Start from the upstream CLI/MCP contract and its tests (`upstream:src/`, `upstream:tests/`, `upstream:docs/`), then design idiomatic Rust that satisfies it. Do not transliterate TypeScript.
- Preserve externally observable contracts unless the maintainer decides otherwise: CLI commands and flags, MCP tool names, JSON Schemas, error contracts, and Evidence shapes. Record intentional divergences in the change description.
- Rust first. Replace Node.js runtime code, npm-installed helpers, and the Node native addon (`upstream:native/windows`) with Rust. Code that must run inside a foreign host stays in that host's language and stays minimal: Ghidra/JADX/NativeAOT scripts (Java), Hopper/Cutter/LLDB/pwndbg/mitmproxy plugins (Python), and macOS UI/process helpers (Swift) under `upstream:bridge/`. Move its logic to the Rust side when practical. Do not add a Node.js dependency to `trunk`.
- Port a capability's tests with it. Prefer parity checks that compare Rust output with upstream behavior on the same fixtures. Report which parity was verified and which was not.
- Track upstream changes on the `upstream` branch. When porting a capability, check `git log upstream -- PATH` for fixes since it was last ported.

## Architecture and Cleanup

Organize the code as a Cargo workspace. Dependencies flow inward: domain semantics and contracts, provider adapters, shared application workflows, then CLI/MCP adapters (binaries). Enforce direction through crate boundaries, so inner crates never depend on outer ones. Keep engine protocols and provider-specific code out of domain/application crates. See `upstream:docs/architecture.mermaid` for the reference composition and keep a Rust equivalent current when changing composition.

Give each interpretation and resource a clear owner. Consumers must use that owner's parsed facts rather than reinterpret raw source. Preserve identity, omission, uncertainty, and source evidence across boundaries. Retain ownership of resources whose cleanup failed. Centralize child-process supervision and identity in one shared module (the port of `upstream:src/process/`) and reuse it; a PID and executable path alone do not establish ownership after exit or reuse. Use RAII (`Drop`) for cleanup only where failure can still be observed and reported; fallible cleanup needs an explicit method that returns `Result`.

Keep proof of ownership separate from validity, editability, and readiness. Malformed owned data may still be safely removable. Unresolved identity or applicability must remain unknown rather than be treated as absent, foreign, or aligned.

For lifecycle changes, follow upstream's ownership and completion invariants (`upstream:docs/tool-design.md`, "Own the lifecycle") and select the applicable lifecycle regressions (`upstream:docs/testing.md`, "Lifecycle regressions"). Include late handshakes, cancellation during final cleanup, mixed child outcomes, and cleanup retry where those stages exist; active-execution cancellation alone does not cover finalization. In async code, treat future drop as cancellation and make cleanup cancellation-safe.

Before adding complexity for a speculative or vanishingly unlikely race or security edge case, explain the concrete failure mode, likelihood, and complexity cost to the user and get their buy-in. Do not silently expand scope for theoretical robustness.

Assess brittleness in touched code during implementation, debugging, review, and maintenance. Fix the producing representation or ownership rule before adding downstream repairs. Normalize once at the owning boundary using format-aware parsers. Remove superseded representations, aliases, wrappers, and redundant tests after verifying affected consumers. Introduce abstractions (traits, generics, macros) only when they remove observed complexity.

When fixing a bug, inspect the producing boundary and affected consumers for duplicated interpretation or unclear ownership. Complete any directly related refactor in the same change and remove superseded code. Passing regression tests alone does not establish that the brittleness is resolved. If related cleanup remains, explain what remains and why.

After confirming a bug, search sibling adapters, consumers, and similar workflows for the same failure. Also check whether upstream has the same bug. Verify suspected matches, record working comparisons, and group findings by root cause instead of filing duplicate reports.

When addressing a review thread, inspect the producing boundary and affected consumers for brittleness. Complete directly related refactoring in the same change. Before resolving the thread, explain the root cause, structural fix, validation, and any remaining cleanup.

Parse unknown boundary values into typed values and model expected failures with error enums and `Result`. Never panic on external input. Reserve `unwrap`/`expect` for documented invariants, and avoid `unsafe` unless required for FFI or a measured need; document each `unsafe` block's safety argument. Preserve partial facts and meaningful failure reasons. Keep identity and lookup values separate from display formatting (use newtypes, not `String`); preserve source values and explicit unknowns when normalization loses information. Absolute paths, file URLs, and HTTP paths have different semantics; do not round-trip `Path`/`OsStr` through lossy UTF-8.

Validate advertised JSON Schemas, whether generated or hand-written, against their declared dialect and actual clients. Bind handlers to named contracts with exact types; catalog ordering must never select an operation or schema.

## Performance

Design analysis workflows and agent interfaces for efficiency from the first implementation. Correctness, useful answers, Evidence provenance, caller choices, compatibility, and safe resource bounds remain required.

Optimize in this order:

1. Agent tokens and context. Return the smallest sufficient answer with necessary provenance, coverage, and limitations. Use task selection, summaries, paging, and retained Evidence where supported; honor requested detail and keep complete Evidence accessible. Count the whole task, including schemas, extra calls, and retries.
2. Analysis time. Reuse validated results and shared work. Cache keys must cover result-affecting inputs; define invalidation and lifetime. Validate freshness before reporting cached live state as current.
3. CPU and memory. Avoid unnecessary work and copies; prefer borrowing and streaming over buffering whole inputs; bound concurrency, retained state, and serialization growth.

Reserve performance measurements for changes that target performance or have a concrete regression concern. Routine cleanup uses correctness checks; changes to helper calls, imports, or representations alone do not require synthetic benchmarks. When measurement is warranted, measure representative completed tasks and compare equivalent workflows before and after, including the upstream equivalent where available. Report token usage, elapsed time, CPU time, and peak process-family memory. Separate cold and warm runs, label estimates, and state unmeasured costs. Fewer bytes alone do not establish fewer tokens or faster analysis.

## Development

Pin the toolchain in `rust-toolchain.toml` and the MSRV in the workspace `Cargo.toml`. Commit `Cargo.lock`. Add dependencies at the workspace level, prefer well-maintained crates, and justify each new one.

Development tasks use the `cargo xtask` pattern (`xtask/`, std-only, aliased in `.cargo/config.toml`). Add new repository automation as xtask tasks, not shell scripts or npm scripts. Extra arguments are forwarded to the underlying cargo command.

- `cargo xtask check`: type-check every workspace target.
- `cargo xtask fmt`: format (`--check` to verify only).
- `cargo xtask clippy`: lints with `-D warnings`.
- `cargo xtask test`: run tests (`-p CRATE` or a test name filter for focused runs).
- `cargo xtask coverage`: tests under `cargo-llvm-cov` (bring-your-own; `--html` or `--lcov --output-path PATH` for reports).
- `cargo xtask doc`: build documentation with `-D warnings`.
- `cargo xtask ci`: the full gate: fmt check, clippy, test, doc.

Run the checks relevant to the change. Run `cargo xtask ci` before declaring broad changes done.

When changing installers or setup recovery, follow upstream's installer guidance (`upstream:docs/testing.md`, "Checking installers and publisher downloads").

Coordinate expensive checks across agents. If a test unexpectedly consumes heavy CPU, stop its owned process family and profile a bounded representative case before retrying. Inspect production work, fixture generation, subprocesses, and repeated setup; preserve regression coverage when optimizing.

Generated outputs (catalogs, schemas, packaged skills) must come from source contracts in the repository; edit the source and regenerate. Never commit binaries, provider project documents, credentials, `target/`, or local planning artifacts.

## Tool and Test Changes

For tool design, follow `upstream:docs/tool-design.md`: start from the analyst question, reuse existing contracts, preserve caller choices, and return useful evidence inline. Limits must follow real format, protocol, authority, or resource constraints. Account for representation expansion before allocation; derive completeness from examined coverage.

For user- or agent-facing tool problems, prioritize fixing the owning behavior, contract, and actionable result or recovery at the point of use. Document the result in product docs when explanation is needed. Add skill guidance only for workflow judgment or context that the tool cannot reasonably convey; do not use a skill as the primary repair for a discoverability or contract defect.

For test changes or provider claims, use `upstream:docs/testing.md`. Select applicable boundary regressions for parser, inventory, snapshot, and projection fixes. Prefer real public CLI/MCP workflows (integration tests under `tests/`), then production-boundary integration, then producer goldens. Keep unit tests (`#[cfg(test)]`) for distinct semantics that stronger workflows cannot reliably reproduce. Consider property tests or fuzzing for binary-format parsers. Preserve malformed-input, cancellation, cleanup, permission, capacity, and target-identity coverage when pruning. Report unverified coverage explicitly; simulated providers do not establish real-provider behavior.

Use Conventional Commit subjects and PR titles. Mark breaking changes with `!` or a `BREAKING CHANGE:` footer. Describe behavior changes, relevant validation, upstream parity, and real-provider verification scope.

## Issue Reports

Keep reports concise and cite the smallest useful evidence. Distinguish observed results, source-derived reasoning, hypotheses, and proposed checks. Say whether the issue is specific to the Rust port or also present upstream. Never claim runtime reproduction or measurements you did not perform. Use `NOT_ENOUGH_INFO` with an explanation for missing narrative answers or evidence. Incomplete reports, source-only findings, and early feature or design ideas are welcome when their limitations are explicit.

## Pull Request Readiness

AI-assisted contributions are welcome; a human must review and own the final diff, check the validation evidence and its limitations, and explicitly declare the PR ready for review. Never attest to human review on their behalf.

Keep the PR body concise and current, with the concrete problem, observable outcome, approach, and evidence. Report only checks that actually ran; distinguish source-derived conclusions, proposed checks, and unavailable coverage. Address actionable automated review findings and explain disagreements. Preserve the PR's draft status unless the user asks to change it.
