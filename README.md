# Kvist Passwordless Auth

Small, storage-independent passwordless authentication primitives for
[Kvist](https://github.com/kvist-lang/kvist):

```text
identity -> challenge -> proof -> verification -> session
```

The package provides high-entropy magic-link proofs, HMAC-protected numeric
codes, explicit challenge transitions, opaque server-side session credentials,
and issuance-limit decisions. It does not own users, authorization, HTTP,
email, UI, or a database.

Place this repository in the consumer's dependency folder and import it by
relative path:

```clojure
(import auth "deps/passwordless-auth")
```

Run the tests with:

```sh
kvist test tests/passwordless-auth-tests.kvist
```

## Ownership

Returned strings and records own their string fields. Delete them with the
matching helper:

- `delete-issued-challenge!`
- `delete-challenge-result!`
- `delete-issued-session!`
- `delete-session-result!`

Credential hash functions return owned strings when `ok` is true. Challenge
and session inputs borrow strings from the caller.

Use `issue-challenge` and `issue-session` in normal application flows. Storage
adapters and deterministic tests may use `challenge-from-proof` and
`session-from-credential`; these apply the same validation and hashing while
accepting caller-supplied plaintext values. Delete successful returned records
with `delete-challenge!` or `delete-session!`.

## Persistence

Persist only `Challenge` and `Session` records, never the plaintext proof or
credential returned alongside them. A store must evaluate
`verify-challenge`, then apply its requested transition atomically under a row
lock or compare-and-set guard. Missing challenge rows map to `Invalid-Proof`.

Times are Unix milliseconds. Expiry is exclusive: a value is expired when
`now-ms >= expires-at-ms`.

See [DESIGN.md](DESIGN.md) and [SECURITY.md](SECURITY.md) for the complete
boundary and security requirements.
