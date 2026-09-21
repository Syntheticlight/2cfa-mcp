# Contributing to 2cfa-mcp

Thanks for considering a contribution.

## Before you start

For bug fixes and small improvements, feel free to open a pull request directly. For larger behavior changes, opening an issue first is recommended so the direction can be discussed before implementation.

Please do **not** open a public issue for a security vulnerability. See [SECURITY.md](SECURITY.md).

## Development

Requirements:

- Go 1.26.8 or newer

Before opening a pull request, run:

```bash
gofmt -w .
go vet ./...
go test ./...
govulncheck ./...
```

The repository CI runs the same core checks, plus cross-platform builds.

## Pull requests

Keep pull requests focused and easy to review.

Please:

- explain what changed and why;
- include tests for behavior changes when practical;
- avoid unrelated refactors in the same PR;
- do not commit secrets, tokens, private keys, `.env` files, or generated binaries;
- preserve the project's existing security model unless the change explicitly intends to modify it.

All pull requests must pass CI before merging. Final merge decisions are made by the maintainer.

## Style

Follow normal Go conventions and keep the implementation simple. Prefer clear, auditable behavior over unnecessary abstraction.
