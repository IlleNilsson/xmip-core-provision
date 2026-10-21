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
`xmip-core-library-tls`. Not yet read by `xmip-service`, which starts no
provisioner (open problem 27). A provisioned key is a private PEM file in the
purpose's place, readable by the Service Identity alone, not sealed under the
key home's key-encryption key (ADR-0063 clause 4).

## Verification

`cargo clippy --all-targets -- -D warnings` and `cargo test`: an identity is
read back whole, its key, folder and place the owner's alone (the mode on
Unix, the access list on Windows); a crash after a new generation is written
and before the switch, or halfway through writing one, leaves the old chain
with the old key, and the next write sweeps both; a `current` naming no
generation is refused; an operator's key and request are written private and
never over a file. Run on Windows and on Linux. The workflow is manual-only
and calls the versioned shared workflow at `IlleNilsson/.github@v1`.
