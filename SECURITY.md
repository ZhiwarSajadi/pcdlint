# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ |
| 0.1.x   | ❌ (please upgrade) |

## Reporting a vulnerability

Please report privately through
[GitHub Security Advisories](https://github.com/ZhiwarSajadi/pcdlint/security/advisories/new)
rather than a public issue, so a fix can land before disclosure. You should
hear back within a few days.

## What counts

pcdlint runs offline over source files you point it at: it opens no network
connections, executes no code, and has no runtime attack surface. The things
that matter here are therefore:

- a bug in `--fix` that corrupts or silently rewrites source it was not
  asked to change;
- a path traversal or unexpected file read while walking a directory;
- anything that lets one file's content influence the analysis of another.

A rule simply failing to report a pattern is a correctness bug, not a
vulnerability — file that as a normal issue.
