# xmip-core-provision

Certificate provisioning (ADR-0034): where a node's certificate comes from,
kept apart from how it is used. Created 2026-10-13 (ADR-0033, amendment
2026-10-13); the owner: Let's Encrypt *as an option*, never required.

## What it is

- **`Source`** — obtains a certificate for an `Order`: a `Purpose` and the
  DNS names it is for, and the purpose's place, where a source keeps its own
  state between orders. A provider ships a source by implementing it.
- **`Purpose`** — `receive`, what a Party reaches, server authentication
  alone; `node`, between nodes, server and client authentication.
- **`Provisioner`** — one purpose's certificate kept in its place, read back
  after a restart, and obtained again at two thirds of the life it was
  issued with, read from the certificate itself: no lifetime is assumed
  (CA/Browser Forum ballot SC-081 is shortening public ones). A renewal
  that fails keeps the certificate held until it expires.
- **`Provisioned`** — the chain, leaf first, its key and the anchors, PEM,
  as `xmip-core-library-tls` takes them.
- **`KeyPair`, `csr`, `Draft`** — the P-256 key, the PKCS #10 request and
  the X.509 certificate, written once over `xmip-core-library-asn1` and
  signed with aws-lc-rs, the crypto the TLS library already builds; `serves`
  reads whether a certificate authenticates what its purpose needs.
- **`read`, `NAMES`, `FILES`, `Files`** — `[provision.<purpose>]` read
  through the chosen technology's settings declaration, refused in words
  when incomplete; a table with no `source` is the operator's own files.

## Its technologies

Mounted beside `.src` (ADR-0049):

| technology | what |
| --- | --- |
| `acme` | RFC 8555 against any directory a node names; http-01 on any port, dns-01 through a provider's `DnsWriter` |
| `internal-ca` | the cluster's own authority, issuing node certificates for server and client authentication, served over ACME |
| `self-signed` | a lone offline node's certificate, its own anchor |

`platform` — a managed platform's issuer — is reserved in `architecture.toml`.

## What it is not

Not usage: presenting and verifying a certificate is
`xmip-core-library-tls`. Not yet read by `xmip-service`, which starts no
provisioner (open problem 27). A provisioned key is a PEM file in the
purpose's place, not sealed under the key home (ADR-0063 clause 4).

## Verification

`cargo clippy --all-targets -- -D warnings` and `cargo test`. The workflow is
manual-only and calls the versioned shared workflow at `IlleNilsson/.github@v1`.
