# Design

## Boundary

The reusable boundary is credential mechanics, not an application login flow.
The application owns identity normalization, account lookup or creation,
authorization, URLs, email, cookies, HTTP, durable rate-limit counts, and
transactions.

Identity, subject, and metadata are opaque strings. This keeps the package
independent of serialization and domain models. Consumers may store IDs, EDN,
JSON, or another stable representation.

## Challenges

`issue_challenge` returns the persisted record and its plaintext proof. The
record contains only a versioned proof hash. Magic links use 32 random bytes
and SHA-256. Numeric codes use HMAC-SHA-256 and require an application-held key
of at least 32 bytes.

`verify_challenge` is a pure decision over a record and an explicit time. It
returns one stable status and at most one transition:

- `Verified` with `Consume`
- `Invalid-Proof`
- `Expired`
- `Consumed`
- `Attempts-Exhausted`
- a failed code attempt with `Record-Failure`

The store must select, verify, and apply the transition atomically. The core
does not hide that transaction behind callbacks.

The optional `conformance` subpackage defines callback tables for challenge
and session stores. Its reusable assertions include actual thread races for
double consumption and code-attempt saturation; this lets each database
adapter prove the atomicity requirement against its own transaction model.

## Sessions

`issue_session` returns an opaque credential once and a record containing only
its versioned hash. `check_session` classifies a loaded record as `Active`,
`Invalid-Session`, `Expired-Session`, or `Revoked-Session`. Active results omit
the credential hash.

## Memory

Issuance records and credentials own their strings. Their constructors accept
an optional allocator, and their delete helpers accept the allocator used to
create them. Verification and session-classification results are borrowed
views over the input record; they allocate nothing and are valid only while
that record remains alive.
