# LEARNING

What the agent has learned from the maintainer's instructions. Add to this as new guidance comes in.

## Project vision

- `rea-rs` is **more than a fork** of [rea](https://github.com/morluto/rea).
- Goal: use **Rust as much as possible**.
- `AGENTS.md` is adapted from upstream's `AGENTS.md` for the Rust port. Keep the upstream principles and replace the TypeScript/Node.js tooling with Rust/Cargo.

## Porting approach

- Port REA to Rust **incrementally**.
- Step one: repository automation via the **cargo xtask pattern** (check, fmt, clippy, test, coverage).

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
