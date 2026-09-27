# Security model

Magic-link and session credentials use 32 bytes of cryptographic randomness.
Their SHA-256 hashes are safe lookup keys because the source credentials have
256 bits of entropy.

Numeric codes are low entropy and therefore require HMAC-SHA-256 with an
application-held key of at least 32 bytes. HMAC limits offline recovery after
a database leak; short expiry, atomic attempt limits, and issuance throttling
are still required against online guessing.

Plaintext proofs and credentials must appear only in issuance results and
delivery/cookie handling. Never persist them or copy them into metadata. Hash
comparisons inside the package are constant-time.

Challenge verification and its transition must be one atomic storage
operation. Otherwise two concurrent requests can both consume a one-time
proof, or failed code attempts can be lost.

The package does not provide authorization, password hashing, passkeys, OAuth,
email, cookie policy, CSRF defense, generic rate limiting, or audit storage.

