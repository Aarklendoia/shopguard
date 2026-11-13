# Security policy

## Supported versions

Only the latest release of each component receives security fixes:

| Component                     | Supported            |
| ----------------------------- | -------------------- |
| `shopguard-worker` (image)    | latest `worker-v*`   |
| `os-shopguard` (OPNsense)     | latest `plugin-v*`   |

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through
[GitHub private vulnerability reporting](https://github.com/Aarklendoia/shopguard/security/advisories/new).

Include the affected component and version, a description of the issue and, if possible,
steps to reproduce. You should get a first answer within 7 days. Once a fix is released,
the advisory is published and credits the reporter unless they prefer otherwise.

## Verifying release images

Worker images are signed with cosign (keyless, GitHub OIDC) and ship with an SBOM and
build provenance:

```sh
cosign verify ghcr.io/aarklendoia/shopguard-worker:<version> \
  --certificate-identity-regexp '^https://github.com/Aarklendoia/shopguard/\.github/workflows/release\.yml@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
