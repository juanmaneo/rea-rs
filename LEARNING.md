# LEARNING

What the agent has learned from the maintainer's instructions. Add to this as new guidance comes in.

## Project vision

- `rea-rs` is **more than a fork** of [rea](https://github.com/morluto/rea).
- Goal: use **Rust as much as possible**.
- `AGENTS.md` is adapted from upstream's `AGENTS.md` for the Rust port. Keep the upstream principles and replace the TypeScript/Node.js tooling with Rust/Cargo.

## Porting approach

- Port REA to Rust **incrementally**.
- Step one: repository automation via the **cargo xtask pattern** (check, fmt, clippy, test, coverage).
- Scope: **all of the code on upstream `main`**, mirrored locally in the `upstream` branch. The goal is the whole product, so [PORTING.md](PORTING.md) inventories every upstream area, its target crate, and its status. It is a multi-session effort and each capability lands as its own commit with its own tests.
- Order: foundations first (xtask, then shared contracts and the host boundary), then one capability at a time end to end (domain, provider, application, CLI).

## Scope decisions

- **Linux and FreeBSD are the primary platforms**, for both development and use. Running on macOS or Windows hosts is a non-goal: do not port host-specific code for them, add `cfg` branches for them, or test on them. Prefer portable POSIX/`cfg(unix)` code. When behaviour differs between Linux and FreeBSD (errno values, `/proc` versus `sysctl`/`procstat`, package databases), handle both and gate with `target_os`. Type-check FreeBSD with `--target x86_64-unknown-freebsd`. Static analysis of their binary formats (PE, Mach-O, code signatures, Apple crash reports, Swift metadata) is still in scope: it only reads bytes.

These resolve the "needs a scope decision" items from [PORTING.md](PORTING.md). Open questions are listed there too.

- **No Node.js anywhere.** Not as a runtime, a helper process, or an optional native binding. Whatever upstream runs through Node is ported to Rust.
- **JavaScript source maps: port the codec to Rust.** Upstream decodes with the pinned `@jridgewell/trace-mapping` inside an owned Node child (`upstream:src/javascript/sourceMaps/`). The Rust port replaces that child. Keep upstream's observable behaviour: the 4 MiB map input and 32 MiB output budgets, and every equal-position candidate preserved.
- **Frida: port to Rust.** Upstream uses the Node `frida` package (17.23.2, optional dependency; `upstream:src/frida`). FFI is acceptable only if kept very limited: one small crate holds the FFI and every `unsafe` block, each with a safety argument. The rest of the workspace keeps `unsafe_code = deny`.
- **Target execution, injection, and mutation run in containers (podman), not on the host.** Podman is bring-your-own, like Ghidra and IDA: REA never installs or upgrades it. Container policy:
  - **Image:** built from a Containerfile kept in the repo. The Linux one must build unchanged with Docker, Podman, and Buildah (the FreeBSD one with Podman and Buildah), so use only the OCI/Dockerfile syntax all three accept (no BuildKit-only extensions such as `RUN --mount`, heredocs, or `# syntax=` directives).
  - **Network:** off by default. Access only by explicit caller opt-in.
  - **Privileges:** root inside the container is allowed when needed, but never root on the host. Container root must map to an unprivileged host user (a user namespace). In practice that means rootless Podman or Docker in rootless or `userns-remap` mode. A default rootful Docker daemon gives container root real host root, so REA must refuse it (fail closed) rather than run there.
  - **Containers follow the host OS.** On a Linux host, Linux containers (Docker, Podman, or Buildah). On a FreeBSD host, FreeBSD containers: Podman/Buildah with FreeBSD jails, since Docker does not run on FreeBSD. So the repo keeps a Linux Containerfile and a FreeBSD Containerfile.
  - **Windows and macOS targets:** not supported for execution, injection, or mutation. REA refuses them with a clear error (fail closed). There is no VM or host fallback.
  - **Least privilege: grant as little as possible.** Drop every capability by default (`--cap-drop=ALL`), set `no-new-privileges`, and add back only what a specific operation proves it needs, for that run only (for example `SYS_PTRACE` for a debugger or Frida run, and only if ptracing its own child is not enough). Keep the engine's default seccomp profile; never run `seccomp=unconfined` or `--privileged`. A custom profile only if it is narrower than the default. On FreeBSD jails the same rule applies to jail parameters: leave every `allow.*` off unless an operation needs it.
  - Still open: mounts and container ownership (see [PORTING.md](PORTING.md)). Execution capabilities wait for these.
- **Tests are ported to `cargo test`.** Upstream's vitest, fast-check, and Stryker setup is not carried over.
- **Playwright: dropped.** It has no place in the Rust port; do not port it, wrap it, or look for a Rust clone of it. Upstream uses `playwright-core` at runtime (13 files, about 8.7k lines under `upstream:src/browser`) for `capture-browser-scenario`, `capture-electron-scenario`, and related commands.
- **Blitz** ([DioxusLabs/blitz](https://github.com/DioxusLabs/blitz)) is the suggested Rust engine for rendering HTML/CSS (SSR). Per its README it is beta, renders HTML and CSS through Stylo, Taffy, and Parley, and deliberately has **no JavaScript engine** (no websockets, localStorage, and so on). It fits rendering static or server-rendered HTML; it cannot observe script execution.

## Repository layout

| Branch     | Tracks                | Purpose                                                        |
| ---------- | --------------------- | -------------------------------------------------------------- |
| `trunk`    | `origin/trunk`        | Default branch for `rea-rs` work. Started as an empty orphan branch. |
| `upstream` | `upstream/main`       | Mirror of the official rea repo (this was `main`).             |

| Remote     | URL                                       |
| ---------- | ----------------------------------------- |
| `origin`   | `git@github.com:juanmaneo/rea-rs.git`     |
| `upstream` | `https://github.com/morluto/rea.git`      |

- `origin/main` stays on the remote. **Do not delete it.**
- Making `trunk` the default branch on GitHub is the maintainer's job.

## Agent rules

- **No remote git operations.** No `push`, `fetch`, `pull`, `clone`, `ls-remote`, or anything else that contacts or changes a remote. The maintainer does all syncing.
- Local git operations are fine.
- **Always commit locally when a task is finished.** Use Conventional Commit subjects. Never push.
- Only do what's asked. When a follow-up is offered and declined, drop it.

## Communication

- The maintainer gives short, direct instructions and expects short, direct replies.
