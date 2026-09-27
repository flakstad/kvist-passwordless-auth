package passwordless_auth

import "core:mem"
import "core:strings"
import "core:testing"

TEST_NOW_MS :: i64(1_790_244_000_000)
TEST_CODE_KEY :: "a-test-only-otp-pepper-that-is-long"

@(test)
secret_formats_match_the_clojure_reference :: proc(t: ^testing.T) {
	plain, plain_ok := hash_secret("bearer")
	defer if plain_ok do delete(plain)
	keyed, keyed_ok := hash_secret_with_key("123456", TEST_CODE_KEY)
	defer if keyed_ok do delete(keyed)
	legacy, legacy_ok := legacy_sha256_hex("bearer")
	defer if legacy_ok do delete(legacy)

	testing.expect(t, plain_ok && keyed_ok && legacy_ok)
	testing.expect_value(t, plain,
		"v1:sha256:JFStYcKswE8KIPq_fyvJbyjRnENAUv3v27UbRv5TT4k")
	testing.expect_value(t, keyed,
		"v1:hmac-sha256:q00LtxJMyvo6Sz3WivnhdwlpEbYHiy8J-RHLNjJkBZU")
	testing.expect_value(t, legacy,
		"2454ad61c2acc04f0a20fabf7f2bc96f28d19c434052fdefdbb51b46fe534f89")
	testing.expect(t, matches_secret(plain, "bearer"))
	testing.expect(t, !matches_secret(plain, "wrong"))
	testing.expect(t, matches_secret(legacy, "bearer"))
	testing.expect(t, matches_secret_with_key(keyed, "123456", TEST_CODE_KEY))
	testing.expect(t, !matches_secret_with_key(keyed, "123456", "wrong"))
}

@(test)
generated_credentials_have_safe_shapes :: proc(t: ^testing.T) {
	first, first_ok := random_token()
	defer if first_ok do delete(first)
	second, second_ok := random_token()
	defer if second_ok do delete(second)
	code, code_ok := random_code()
	defer if code_ok do delete(code)

	testing.expect(t, first_ok && second_ok && code_ok)
	testing.expect_value(t, len(first), 43)
	testing.expect(t, first != second)
	testing.expect_value(t, len(code), 6)
	for character in transmute([]byte)code {
		testing.expect(t, '0' <= character && character <= '9')
	}
	_, invalid_ok := random_code_with_digits(5)
	testing.expect(t, !invalid_ok)
}

@(test)
magic_link_is_single_use_and_expires_at_the_boundary :: proc(t: ^testing.T) {
	issued, ok := issue_challenge({
		id       = "challenge-1",
		identity = "CaseSensitiveIdentity",
		method   = .Magic_Link,
		metadata = "{:intent :sign-in}",
		now_ms   = TEST_NOW_MS,
	})
	testing.expect(t, ok)
	if !ok do return
	defer delete_issued_challenge(issued)

	testing.expect_value(t, issued.record.expires_at_ms, TEST_NOW_MS + 900_000)
	testing.expect_value(t, issued.record.max_attempts, i64(1))
	testing.expect(t, !strings.contains(issued.record.proof_hash, issued.proof))

	selector, selected := challenge_selector(.Magic_Link, "", issued.proof)
	defer if selected do delete(selector)
	testing.expect(t, selected)
	testing.expect_value(t, selector, issued.record.proof_hash)

	result := verify_challenge(&issued.record, .Magic_Link, issued.proof, "", TEST_NOW_MS)
	defer delete_challenge_result(result)
	testing.expect_value(t, result.status, Challenge_Status.Verified)
	testing.expect(t, result.has_challenge)
	testing.expect_value(t, result.challenge.identity, "CaseSensitiveIdentity")
	apply_challenge_transition(&issued.record, result.transition)

	again := verify_challenge(&issued.record, .Magic_Link, issued.proof, "", TEST_NOW_MS)
	defer delete_challenge_result(again)
	testing.expect_value(t, again.status, Challenge_Status.Consumed)

	issued.record.consumed = false
	expired := verify_challenge(
		&issued.record,
		.Magic_Link,
		issued.proof,
		"",
		issued.record.expires_at_ms,
	)
	defer delete_challenge_result(expired)
	testing.expect_value(t, expired.status, Challenge_Status.Expired)
}

@(test)
code_failures_exhaust_the_attempt_budget :: proc(t: ^testing.T) {
	issued, ok := issue_challenge({
		id           = "challenge-2",
		identity     = "user-1",
		method       = .Code,
		max_attempts = 2,
		hash_key     = TEST_CODE_KEY,
		now_ms       = TEST_NOW_MS,
	})
	testing.expect(t, ok)
	if !ok do return
	defer delete_issued_challenge(issued)

	first := verify_challenge(&issued.record, .Code, "000000", TEST_CODE_KEY, TEST_NOW_MS)
	defer delete_challenge_result(first)
	testing.expect_value(t, first.status, Challenge_Status.Invalid_Proof)
	apply_challenge_transition(&issued.record, first.transition)

	final := verify_challenge(&issued.record, .Code, "000000", TEST_CODE_KEY, TEST_NOW_MS)
	defer delete_challenge_result(final)
	testing.expect_value(t, final.status, Challenge_Status.Attempts_Exhausted)
	apply_challenge_transition(&issued.record, final.transition)

	locked := verify_challenge(&issued.record, .Code, issued.proof, TEST_CODE_KEY, TEST_NOW_MS)
	defer delete_challenge_result(locked)
	testing.expect_value(t, locked.status, Challenge_Status.Attempts_Exhausted)
}

@(test)
session_lifecycle_hides_the_credential_hash :: proc(t: ^testing.T) {
	issued, ok := issue_session({
		id       = "session-1",
		subject  = "user-42",
		ttl_ms   = 1_800_000,
		metadata = "{}",
		now_ms   = TEST_NOW_MS,
	})
	testing.expect(t, ok)
	if !ok do return
	defer delete_issued_session(issued)

	testing.expect(t, !strings.contains(issued.record.credential_hash, issued.credential))
	active := check_session(&issued.record, TEST_NOW_MS)
	defer delete_session_result(active)
	testing.expect_value(t, active.status, Session_Status.Active)
	testing.expect(t, active.has_session)
	testing.expect_value(t, active.session.subject, "user-42")

	expired := check_session(&issued.record, issued.record.expires_at_ms)
	defer delete_session_result(expired)
	testing.expect_value(t, expired.status, Session_Status.Expired_Session)

	issued.record.revoked = true
	issued.record.revoked_at_ms = TEST_NOW_MS
	revoked := check_session(&issued.record, TEST_NOW_MS)
	defer delete_session_result(revoked)
	testing.expect_value(t, revoked.status, Session_Status.Revoked_Session)
}

@(test)
deterministic_adapter_constructors_use_the_same_rules :: proc(t: ^testing.T) {
	challenge, challenge_ok := challenge_from_proof({
		id           = "known-id",
		identity     = "known-user",
		method       = .Code,
		ttl_ms       = 60_000,
		max_attempts = 3,
		metadata     = "{}",
		hash_key     = TEST_CODE_KEY,
		now_ms       = TEST_NOW_MS,
	}, "123456")
	testing.expect(t, challenge_ok)
	if challenge_ok {
		defer delete_challenge(challenge)
		testing.expect(t, matches_secret_with_key(
			challenge.proof_hash,
			"123456",
			TEST_CODE_KEY,
		))
	}

	session, session_ok := session_from_credential({
		id       = "known-session",
		subject  = "known-user",
		ttl_ms   = 60_000,
		metadata = "{}",
		now_ms   = TEST_NOW_MS,
	}, "known-credential")
	testing.expect(t, session_ok)
	if session_ok {
		defer delete_session(session)
		testing.expect(t, matches_secret(session.credential_hash, "known-credential"))
	}
}

@(test)
issuance_policy_has_stable_boundaries :: proc(t: ^testing.T) {
	testing.expect(t, recommended_issuance_decision(4, 19).allowed)
	identity_limited := recommended_issuance_decision(5, 0)
	client_limited := recommended_issuance_decision(0, 20)
	testing.expect(t, !identity_limited.allowed)
	testing.expect_value(t, identity_limited.reason, Issuance_Reason.Identity_Limit)
	testing.expect(t, !client_limited.allowed)
	testing.expect_value(t, client_limited.reason, Issuance_Reason.Client_Limit)
}

@(test)
owned_results_release_all_memory :: proc(t: ^testing.T) {
	tracker: mem.Tracking_Allocator
	mem.tracking_allocator_init(&tracker, context.allocator)
	defer mem.tracking_allocator_destroy(&tracker)
	context.allocator = mem.tracking_allocator(&tracker)

	issued, ok := issue_challenge({
		identity = "tracked-user",
		method = .Code,
		hash_key = TEST_CODE_KEY,
		now_ms = TEST_NOW_MS,
	})
	testing.expect(t, ok)
	if ok {
		result := verify_challenge(&issued.record, .Code, issued.proof, TEST_CODE_KEY, TEST_NOW_MS)
		delete_challenge_result(result)
		delete_issued_challenge(issued)
	}
	testing.expect_value(t, tracker.current_memory_allocated, 0)
	testing.expect_value(t, len(tracker.allocation_map), 0)
}

