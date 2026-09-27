# Odin Passwordless Auth

Small, storage-independent passwordless authentication primitives for
[Odin](https://odin-lang.org/):

```text
identity -> challenge -> proof -> verification -> session
```

The package provides high-entropy magic-link proofs, HMAC-protected numeric
codes, explicit challenge transitions, opaque server-side session credentials,
and issuance-limit decisions. It does not own users, authorization, HTTP,
email, UI, or a database.

Import the package from Odin:

```odin
import auth "deps/passwordless-auth"
```

Run the tests with:

```sh
odin test . -vet -strict-style
odin test ./conformance -vet -strict-style
```

## Ownership

Issuance functions and hash helpers return owned strings and records. They
accept an optional allocator and must be released with the same allocator:

- `delete_issued_challenge`
- `delete_issued_session`

Credential hash functions return owned strings when `ok` is true. Challenge
and session inputs borrow strings from the caller. `verify_challenge` and
`check_session` return non-owning views: their strings remain valid only while
the input record remains alive and must not be deleted separately.

Use `issue_challenge` and `issue_session` in normal application flows. Storage
adapters and deterministic tests may use `challenge_from_proof` and
`session_from_credential`; these apply the same validation and hashing while
accepting caller-supplied plaintext values. Delete successful returned records
with `delete_challenge` or `delete_session`.

All owning procedures default to `context.allocator`, but consumers that use a
temporary arena or tracking allocator should pass it explicitly to both the
constructor and matching delete helper.

## Persistence

Persist only `Challenge` and `Session` records, never the plaintext proof or
credential returned alongside them. A store must evaluate
`verify_challenge`, then apply its requested transition atomically under a row
lock or compare-and-set guard. Missing challenge rows map to `Invalid-Proof`.

Times are Unix milliseconds. Expiry is exclusive: a value is expired when
`now-ms >= expires-at-ms`.

## Store conformance

The `conformance` subpackage supplies callback-based `Challenge_Store` and
`Session_Store` contracts plus reusable assertions for storage adapters. The
challenge suite races successful verification and failed code attempts across
real threads, so adapter callbacks must protect the read/decide/write sequence
with a transaction, row lock, or compare-and-set operation.

```odin
import auth_conformance "deps/passwordless-auth/conformance"

@(test)
adapter_conforms :: proc(t: ^testing.T) {
	auth_conformance.assert_challenge_store(t, &challenge_store)
	auth_conformance.assert_session_store(t, &session_store)
}
```

See [DESIGN.md](DESIGN.md) and [SECURITY.md](SECURITY.md) for the complete
boundary and security requirements.
