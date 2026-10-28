# Contributing

## Workflow

1. Every change starts from an issue.
2. Create a branch from `main` named `<type>/<short-name>`, for example `feat/commit-journal`.
3. Open a pull request that links the issue with `Closes #<number>`.
4. Pull requests are squash-merged once CI passes.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org): `feat:`, `fix:`, `perf:`, `refactor:`, `test:`, `docs:`, `chore:`, `ci:`. Keep the subject short and in the imperative.

## Before opening a pull request

```sh
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test --workspace
```

## Code

- Rust only.
- No `unsafe` outside the crates that need it; every `unsafe` block has a test.
- No new dependency without a review of its source.
- Every change to storage, recovery or delivery comes with tests that fail without it.
