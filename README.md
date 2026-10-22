# xmip-core-provision

Certificate provisioning (ADR-0034): where a node's certificate comes from,
kept apart from how it is used. Created 2026-10-13 (ADR-0033, amendment
2026-10-13); the owner: Let's Encrypt *as an option*, never required.

## What it is

- **`Source`** — obtains a certificate for an `Order`: a `Purpose` and the
  DNS names it is for, and the purpose's place, where a source keeps its own
  state between orders. A provider ships a source by implementing it.
- **`Purpose`** — `receive`, what a Party reaches, server authentication
  alone; `node`, between nodes, server and client authentication;
  `operator`, a person's surface reaching a node's operate listener, client
  authentication alone, its subject the person (ADR-0034, amendment
  2026-10-15). Every rule that follows from a purpose is `purpose.rs`'s:
  what it authenticates, what a person's name may be, and what a request
  for it may ask (`Purpose::admit`).
- **`operator`** — a person's certificate, never obtained by a node:
  `request` makes a fresh key and a request naming the person, and
  `request_into` writes them into a folder as `operator.key` and
  `operator.csr`, private files never written over one, the key never handed
  to the surface that asked; `keep` writes a chain or anchors a surface
  keeps whole and synced, replacing what was there where asked and else
  never over a file already there; `information`
  and `assemble` are its two halves, for a key that never leaves its
  platform's keeper — the keeper's public key read in either form a
  platform hands it, `SubjectPublicKeyInfo` DER or the bare uncompressed
  point, and the keeper's signature verified before the request is handed
  back; `sign` signs a request by the authority `[provision.operator]`
  names (`OPERATOR`: `authority`, the folder it is kept in; `lifetime`,
  thirty days unless said).
- **`Issuer`** — an authority's key and certificate and what it signs: a
  certificate for a key and a purpose, or for a request once its signature
  verifies and its purpose admits it. `internal-ca` signs through it, and so
  does the runtime's export the surfaces call (`xmip_operate.h` section 19),
  since the runtime may link no technology. `Issuer::kept_or_made` keeps an
  authority in a folder and makes one there where none is kept — the
  certificate first, the key last and never over one, both private files —
  for `internal-ca` and `host` alike (moved here from `internal-ca`
  2026-10-21).
- **`host`** — a web host's own certificate on this machine (ADR-0009,
  amendment 2026-10-21): `issue_into` keeps or makes the authority in a
  folder and issues the host a fresh key and a certificate for server
  authentication alone, its subject and only alternative name the name a
  browser reaches it by, written as `host.key` and `host.pem`, private files
  in place of what was there; the same authority signs the tester's
  operator request. The runtime reaches it through `xmip_operate.h` section
  21. `AUTHORITY_LIFETIME`, a year, and `HOST_LIFETIME`, thirty days, are
  the assistant's draft of 2026-10-21, for the owner to strike.
- **`node`** — a node's certificate from the cluster's own authority, for a
  node an environment template puts on a machine of its own (ADR-0015,
  amendment 2026-10-21), since `xmip-service` starts no provisioner yet:
  `issue_into` keeps or makes the authority in a folder and issues the node
  a fresh key and a certificate for server and client authentication, its
  subject the node and its names the node's and every name it is reached
  by, written as `node.pem`, `node.key` and `anchors.pem`, the authority's
  certificate, private files in place of what was there — the files a
  node's `[operate]` names. The same fresh key and issuing as `host`'s
  (`host::Fresh`). The runtime reaches it through `xmip_operate.h` section
  22. `NODE_LIFETIME`, ninety days, is the owner's (2026-10-22).
- **`register`** — the register of an authority kept in a folder (ADR-0034,
  amendment 2026-10-22): every certificate it signs, by any of the ways
  above or by ACME, kept as `issued/<serial>.pem`, each revocation as
  `revoked/<serial>`, and the revocation list it publishes,
  `authority.crl`, made again at every revocation and when a day old,
  valid a week; the plain-HTTP address it publishes at, `published`,
  which every leaf it signs from then names as its CRL distribution point
  (`/crl`) and its issuer's certificate (`/authority.cer`); and its backup,
  the whole folder copied into an empty one, each file private. An
  `Issuer` kept in a folder records what it signs there itself.
- **`crl`** — a version 2 revocation list (RFC 5280 section 5) written,
  signed and read back, its `Reason`s by RFC 5280's words. No OCSP: Let's
  Encrypt has published revocation as lists alone since 2025-08-06.
- **`renewal`** — when a certificate is renewed, said once: its
  `Standing` — current, renewal due, expired — the window ACME Renewal
  Information suggests (RFC 9773), from two thirds to three quarters of
  its life, and a certificate's renewal information identifier, its
  authority key identifier and serial. `renewal_moment`, two thirds of the
  life, is the one moment every reader renews at.
- **`carried`** — a node's certificate across an air gap: `request_into`
  writes a fresh key, `node.next.key`, which stays on the node, and a
  request, `node.csr`; `sign` verifies a carried request, holds it to a
  node's purpose and the names expected, and signs it for ninety days by
  an authority that exists; `import` checks the chain — every signature,
  the leaf for the request's key and names, valid now, reaching the
  node's anchors — before `node.pem`, `node.key` and, where the node held
  none, `anchors.pem` are written.
- **`Parsed`** — a certificate read once: its serial, names, validity,
  key, extensions and the signature over it, which every reader above
  reads from. Every certificate here names its own key and a leaf its
  issuer's (key identifiers, RFC 7093 method 1).
- **A node's certificate always comes from the cluster's authority**:
  `[provision.node]` from a source that trusts the operating system's
  store — a public authority — is refused; its `anchors` must name the
  cluster authority's anchor. Let's Encrypt serves `[provision.receive]`,
  the public server side, alone (the owner, 2026-10-22).
- **Alternative names** — a name that is an IP address is written as an
  `iPAddress`, its four or sixteen octets (RFC 5280 section 4.2.1.6), every
  other name as a `dNSName`: a browser checks `https://127.0.0.1` against
  the first and never the second.
- **`Provisioner`** — one purpose's certificate kept in its place, read back
  after a restart, and obtained again at two thirds of the life it was
  issued with, read from the certificate itself: no lifetime is assumed
  (CA/Browser Forum ballot SC-081 is shortening public ones). A renewal
  that fails keeps the certificate held until it expires.
- **`Provisioned`** — the chain, leaf first, its key and the anchors, PEM,
  as `xmip-core-library-tls` takes them. Kept in the purpose's place as one
  switch: `chain.pem`, `key.pem` and `anchors.pem` are written into a new
  folder `generation-<random>`, each a private file
  (`xmip-core-secret`'s `private_file`: owner-only before its first byte,
  synced), and only then does the file `current` name that folder, replaced
  whole. A reader follows `current`, so it always finds a chain beside its
  own key; a crash at any step leaves the identity kept before, and the
  folder it left is removed at the next write.
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
| `internal-ca` | the cluster's own authority, issuing node certificates for server and client authentication, served over ACME, and signing a person's request |
| `self-signed` | a lone offline node's certificate, its own anchor |

`platform` — a managed platform's issuer — is reserved in `architecture.toml`.

## What it is not

Not usage: presenting and verifying a certificate is
`xmip-core-library-tls`. Not a provisioner in `xmip-service`, which starts
none for its own certificates (open problem 27); it serves the cluster's
authority over ACME where `[provision.node]` says so (`internal-ca`). Not an
OCSP responder. A provisioned key is a private PEM file in the
purpose's place, readable by the Service Identity alone, not sealed under the
key home's key-encryption key (ADR-0063 clause 4).

## Verification

`cargo clippy --all-targets -- -D warnings` and `cargo test`: an identity is
read back whole, its key, folder and place the owner's alone (the mode on
Unix, the access list on Windows); a crash after a new generation is written
and before the switch, or halfway through writing one, leaves the old chain
with the old key, and the next write sweeps both; a `current` naming no
generation is refused; an operator's key and request are written private and
never over a file; `tests/authority.rs`: what a kept authority signs is
registered and names where its list is, a revocation is listed at once,
signed by the authority and never twice, a backup is the same authority,
and a node's certificate carried across an air gap is requested, signed
and imported, each refusal said in words. Run on Windows and on Linux.
The workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
