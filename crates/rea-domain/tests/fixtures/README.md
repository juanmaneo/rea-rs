# rea-domain parity fixtures

## `canonical_digest_vectors.json`

Each entry pairs a JSON `value` with the `digest` that upstream REA's
`digestCanonicalValue` (`upstream:src/domain/canonicalDigest.ts`) produced for
it. The test `canonical_digest_parity` checks that `rea_domain::json::canonical_digest`
produces the same digest.

These vectors were generated once at upstream commit `1cc979c10`. The upstream
module has no dependencies, so it was run directly with Node.js's TypeScript type
stripping. Its parameter-property constructor was rewritten by hand first,
because strip-only mode can't parse that syntax. Node.js is not a dependency of
this repository. To regenerate the vectors after an upstream change, repeat that
one-off run, then compare the result with `git log upstream -- src/domain/canonicalDigest.ts`.
