package conformance

import auth ".."
import "core:mem"
import "core:sync"
import "core:testing"
import "core:thread"

TEST_NOW_MS  :: i64(1_893_488_400_000)
TEST_CODE_KEY :: "passwordless-auth-conformance-only-key-32-bytes"

Challenge_Verify_Request :: struct {
	selector: string,
	method:   auth.Challenge_Method,
	proof:    string,
	hash_key: string,
	now_ms:   i64,
}

Insert_Challenge_Proc :: #type proc(user_data: rawptr, record: ^auth.Challenge) -> bool
Load_Challenge_Proc :: #type proc(
	user_data: rawptr,
	id: string,
	allocator: mem.Allocator,
) -> (auth.Challenge, bool)
Verify_Challenge_Proc :: #type proc(
	user_data: rawptr,
	request: ^Challenge_Verify_Request,
) -> auth.Challenge_Status

Challenge_Store :: struct {
	user_data: rawptr,
	insert:    Insert_Challenge_Proc,
	load:      Load_Challenge_Proc,
	verify:    Verify_Challenge_Proc,
}

Insert_Session_Proc :: #type proc(user_data: rawptr, record: ^auth.Session) -> bool
Load_Session_Proc :: #type proc(
	user_data: rawptr,
	id: string,
	allocator: mem.Allocator,
) -> (auth.Session, bool)
Find_Session_Proc :: #type proc(
	user_data: rawptr,
	credential_hashes: []string,
	allocator: mem.Allocator,
) -> (auth.Session, bool)
Revoke_Session_Proc :: #type proc(user_data: rawptr, id: string, revoked_at_ms: i64) -> bool

Session_Store :: struct {
	user_data: rawptr,
	insert:    Insert_Session_Proc,
	load:      Load_Session_Proc,
	find:      Find_Session_Proc,
	revoke:    Revoke_Session_Proc,
}

Race_Attempt :: struct {
	store:   ^Challenge_Store,
	request: ^Challenge_Verify_Request,
	barrier: ^sync.Barrier,
	status:  ^auth.Challenge_Status,
}

race_verify :: proc(thread_value: ^thread.Thread) {
	attempt := cast(^Race_Attempt)thread_value.data
	sync.barrier_wait(attempt.barrier)
	attempt.status^ = attempt.store.verify(attempt.store.user_data, attempt.request)
}

run_race :: proc(
	store: ^Challenge_Store,
	request: ^Challenge_Verify_Request,
	statuses: []auth.Challenge_Status,
) {
	barrier: sync.Barrier
	sync.barrier_init(&barrier, len(statuses))

	attempts := make([]Race_Attempt, len(statuses), context.temp_allocator)
	threads := make([]^thread.Thread, len(statuses), context.temp_allocator)
	for index in 0 ..< len(statuses) {
		attempts[index] = {
			store   = store,
			request = request,
			barrier = &barrier,
			status  = &statuses[index],
		}
		threads[index] = thread.create(race_verify)
		threads[index].data = &attempts[index]
		thread.start(threads[index])
	}
	for worker in threads do thread.destroy(worker)
}

valid_challenge_store :: proc(store: ^Challenge_Store) -> bool {
	return store != nil && store.insert != nil && store.load != nil && store.verify != nil
}

valid_session_store :: proc(store: ^Session_Store) -> bool {
	return store != nil && store.insert != nil && store.load != nil &&
	       store.find != nil && store.revoke != nil
}

assert_challenge_store :: proc(
	t: ^testing.T,
	store: ^Challenge_Store,
	identity := "passwordless-auth-conformance",
) -> bool {
	testing.expect(t, valid_challenge_store(store))
	if !valid_challenge_store(store) do return false

	magic, magic_ok := auth.issue_challenge({
		identity = identity,
		method   = .Magic_Link,
		now_ms   = TEST_NOW_MS,
	})
	testing.expect(t, magic_ok)
	if !magic_ok do return false
	defer auth.delete_issued_challenge(magic)
	testing.expect(t, store.insert(store.user_data, &magic.record))

	loaded_magic, loaded_magic_ok := store.load(
		store.user_data,
		magic.record.id,
		context.allocator,
	)
	testing.expect(t, loaded_magic_ok)
	if loaded_magic_ok {
		defer auth.delete_challenge(loaded_magic)
		testing.expect_value(t, loaded_magic.proof_hash, magic.record.proof_hash)
		testing.expect(t, loaded_magic.proof_hash != magic.proof)
	}

	wrong_selector, wrong_selector_ok := auth.challenge_selector(.Magic_Link, "", "wrong")
	defer if wrong_selector_ok do delete(wrong_selector)
	testing.expect(t, wrong_selector_ok)
	wrong_request := Challenge_Verify_Request{
		selector = wrong_selector,
		method   = .Magic_Link,
		proof    = "wrong",
		now_ms   = TEST_NOW_MS + 1_000,
	}
	testing.expect_value(
		t,
		store.verify(store.user_data, &wrong_request),
		auth.Challenge_Status.Invalid_Proof,
	)

	selector, selector_ok := auth.challenge_selector(.Magic_Link, "", magic.proof)
	defer if selector_ok do delete(selector)
	testing.expect(t, selector_ok)
	request := Challenge_Verify_Request{
		selector = selector,
		method   = .Magic_Link,
		proof    = magic.proof,
		now_ms   = TEST_NOW_MS + 1_000,
	}
	statuses: [2]auth.Challenge_Status
	run_race(store, &request, statuses[:])
	verified_count := 0
	terminal_count := 0
	for status in statuses {
		if status == .Verified do verified_count += 1
		if status == .Consumed || status == .Invalid_Proof do terminal_count += 1
	}
	testing.expect_value(t, verified_count, 1)
	testing.expect_value(t, terminal_count, 1)

	expiring, expiring_ok := auth.issue_challenge({
		identity = identity,
		method   = .Magic_Link,
		ttl_ms   = 1_000,
		now_ms   = TEST_NOW_MS,
	})
	testing.expect(t, expiring_ok)
	if !expiring_ok do return false
	defer auth.delete_issued_challenge(expiring)
	testing.expect(t, store.insert(store.user_data, &expiring.record))
	expiring_selector, expiring_selector_ok := auth.challenge_selector(
		.Magic_Link,
		"",
		expiring.proof,
	)
	defer if expiring_selector_ok do delete(expiring_selector)
	expiring_request := Challenge_Verify_Request{
		selector = expiring_selector,
		method   = .Magic_Link,
		proof    = expiring.proof,
		now_ms   = expiring.record.expires_at_ms,
	}
	testing.expect_value(
		t,
		store.verify(store.user_data, &expiring_request),
		auth.Challenge_Status.Expired,
	)

	limited, limited_ok := auth.issue_challenge({
		identity     = identity,
		method       = .Code,
		max_attempts = 5,
		hash_key     = TEST_CODE_KEY,
		now_ms       = TEST_NOW_MS,
	})
	testing.expect(t, limited_ok)
	if !limited_ok do return false
	defer auth.delete_issued_challenge(limited)
	testing.expect(t, store.insert(store.user_data, &limited.record))
	limited_request := Challenge_Verify_Request{
		selector = limited.record.id,
		method   = .Code,
		proof    = "000000",
		hash_key = TEST_CODE_KEY,
		now_ms   = TEST_NOW_MS + 1_000,
	}
	for _ in 0 ..< 4 {
		testing.expect_value(
			t,
			store.verify(store.user_data, &limited_request),
			auth.Challenge_Status.Invalid_Proof,
		)
	}
	testing.expect_value(
		t,
		store.verify(store.user_data, &limited_request),
		auth.Challenge_Status.Attempts_Exhausted,
	)
	loaded_limited, loaded_limited_ok := store.load(
		store.user_data,
		limited.record.id,
		context.allocator,
	)
	testing.expect(t, loaded_limited_ok)
	if loaded_limited_ok {
		defer auth.delete_challenge(loaded_limited)
		testing.expect_value(t, loaded_limited.failed_attempt_count, i64(5))
		testing.expect(t, !loaded_limited.consumed)
	}
	limited_request.proof = limited.proof
	testing.expect_value(
		t,
		store.verify(store.user_data, &limited_request),
		auth.Challenge_Status.Attempts_Exhausted,
	)

	replay, replay_ok := auth.issue_challenge({
		identity = identity,
		method   = .Code,
		hash_key = TEST_CODE_KEY,
		now_ms   = TEST_NOW_MS,
	})
	testing.expect(t, replay_ok)
	if !replay_ok do return false
	defer auth.delete_issued_challenge(replay)
	testing.expect(t, store.insert(store.user_data, &replay.record))
	replay_request := Challenge_Verify_Request{
		selector = replay.record.id,
		method   = .Code,
		proof    = replay.proof,
		hash_key = TEST_CODE_KEY,
		now_ms   = TEST_NOW_MS + 1_000,
	}
	testing.expect_value(
		t,
		store.verify(store.user_data, &replay_request),
		auth.Challenge_Status.Verified,
	)
	testing.expect_value(
		t,
		store.verify(store.user_data, &replay_request),
		auth.Challenge_Status.Consumed,
	)

	concurrent, concurrent_ok := auth.issue_challenge({
		identity     = identity,
		method       = .Code,
		max_attempts = 3,
		hash_key     = TEST_CODE_KEY,
		now_ms       = TEST_NOW_MS,
	})
	testing.expect(t, concurrent_ok)
	if !concurrent_ok do return false
	defer auth.delete_issued_challenge(concurrent)
	testing.expect(t, store.insert(store.user_data, &concurrent.record))
	concurrent_request := Challenge_Verify_Request{
		selector = concurrent.record.id,
		method   = .Code,
		proof    = "not-a-code",
		hash_key = TEST_CODE_KEY,
		now_ms   = TEST_NOW_MS + 1_000,
	}
	concurrent_statuses: [10]auth.Challenge_Status
	run_race(store, &concurrent_request, concurrent_statuses[:])
	loaded_concurrent, loaded_concurrent_ok := store.load(
		store.user_data,
		concurrent.record.id,
		context.allocator,
	)
	testing.expect(t, loaded_concurrent_ok)
	if loaded_concurrent_ok {
		defer auth.delete_challenge(loaded_concurrent)
		testing.expect_value(t, loaded_concurrent.failed_attempt_count, i64(3))
	}
	testing.expect_value(
		t,
		store.verify(store.user_data, &concurrent_request),
		auth.Challenge_Status.Attempts_Exhausted,
	)
	return true
}

assert_session_store :: proc(
	t: ^testing.T,
	store: ^Session_Store,
	subject := "passwordless-auth-conformance",
) -> bool {
	testing.expect(t, valid_session_store(store))
	if !valid_session_store(store) do return false

	issued, issued_ok := auth.issue_session({
		subject = subject,
		ttl_ms  = 3_600_000,
		now_ms  = TEST_NOW_MS,
	})
	testing.expect(t, issued_ok)
	if !issued_ok do return false
	defer auth.delete_issued_session(issued)
	testing.expect(t, store.insert(store.user_data, &issued.record))

	loaded, loaded_ok := store.load(store.user_data, issued.record.id, context.allocator)
	testing.expect(t, loaded_ok)
	if loaded_ok {
		defer auth.delete_session(loaded)
		testing.expect_value(t, loaded.credential_hash, issued.record.credential_hash)
		testing.expect(t, loaded.credential_hash != issued.credential)
	}

	wrong_hash, wrong_hash_ok := auth.session_credential_hash("wrong")
	defer if wrong_hash_ok do delete(wrong_hash)
	wrong_hashes := [1]string{wrong_hash}
	_, wrong_found := store.find(store.user_data, wrong_hashes[:], context.allocator)
	testing.expect(t, !wrong_found)

	current, legacy, candidates_ok := auth.session_credential_hash_candidates(issued.credential)
	defer if candidates_ok {
		delete(current)
		delete(legacy)
	}
	testing.expect(t, candidates_ok)
	candidates := [2]string{current, legacy}
	found, found_ok := store.find(store.user_data, candidates[:], context.allocator)
	testing.expect(t, found_ok)
	if found_ok {
		defer auth.delete_session(found)
		testing.expect_value(
			t,
			auth.check_session(&found, TEST_NOW_MS).status,
			auth.Session_Status.Active,
		)
		testing.expect_value(
			t,
			auth.check_session(&found, found.expires_at_ms).status,
			auth.Session_Status.Expired_Session,
		)
	}

	testing.expect(t, store.revoke(store.user_data, issued.record.id, TEST_NOW_MS + 1_000))
	testing.expect(t, store.revoke(store.user_data, issued.record.id, TEST_NOW_MS + 2_000))
	testing.expect(t, !store.revoke(store.user_data, "missing-session", TEST_NOW_MS + 1_000))
	revoked, revoked_ok := store.find(store.user_data, candidates[:], context.allocator)
	testing.expect(t, revoked_ok)
	if revoked_ok {
		defer auth.delete_session(revoked)
		testing.expect_value(
			t,
			auth.check_session(&revoked, TEST_NOW_MS + 2_000).status,
			auth.Session_Status.Revoked_Session,
		)
	}
	return true
}
