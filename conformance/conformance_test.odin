package conformance

import auth ".."
import "core:mem"
import "core:sync"
import "core:testing"

Memory_Store :: struct {
	mutex:           sync.Mutex,
	challenges:      [32]auth.Challenge,
	challenge_count: int,
	sessions:        [8]auth.Session,
	session_count:   int,
}

clone_challenge :: proc(
	record: ^auth.Challenge,
	allocator: mem.Allocator,
) -> (result: auth.Challenge, ok: bool) {
	result = record^
	result.id, ok = auth.clone_string(record.id, allocator)
	if !ok do return
	result.identity, ok = auth.clone_string(record.identity, allocator)
	if !ok {
		delete(result.id, allocator)
		return
	}
	result.proof_hash, ok = auth.clone_string(record.proof_hash, allocator)
	if !ok {
		delete(result.id, allocator)
		delete(result.identity, allocator)
		return
	}
	result.metadata, ok = auth.clone_string(record.metadata, allocator)
	if !ok {
		delete(result.id, allocator)
		delete(result.identity, allocator)
		delete(result.proof_hash, allocator)
	}
	return
}

clone_session :: proc(
	record: ^auth.Session,
	allocator: mem.Allocator,
) -> (result: auth.Session, ok: bool) {
	result = record^
	result.id, ok = auth.clone_string(record.id, allocator)
	if !ok do return
	result.subject, ok = auth.clone_string(record.subject, allocator)
	if !ok {
		delete(result.id, allocator)
		return
	}
	result.credential_hash, ok = auth.clone_string(record.credential_hash, allocator)
	if !ok {
		delete(result.id, allocator)
		delete(result.subject, allocator)
		return
	}
	result.metadata, ok = auth.clone_string(record.metadata, allocator)
	if !ok {
		delete(result.id, allocator)
		delete(result.subject, allocator)
		delete(result.credential_hash, allocator)
	}
	return
}

destroy_memory_store :: proc(store: ^Memory_Store) {
	for index in 0 ..< store.challenge_count {
		auth.delete_challenge(store.challenges[index])
	}
	for index in 0 ..< store.session_count {
		auth.delete_session(store.sessions[index])
	}
}

memory_insert_challenge :: proc(user_data: rawptr, record: ^auth.Challenge) -> bool {
	store := cast(^Memory_Store)user_data
	sync.mutex_lock(&store.mutex)
	defer sync.mutex_unlock(&store.mutex)
	if store.challenge_count >= len(store.challenges) do return false
	copy, ok := clone_challenge(record, context.allocator)
	if !ok do return false
	store.challenges[store.challenge_count] = copy
	store.challenge_count += 1
	return true
}

memory_load_challenge :: proc(
	user_data: rawptr,
	id: string,
	allocator: mem.Allocator,
) -> (auth.Challenge, bool) {
	store := cast(^Memory_Store)user_data
	sync.mutex_lock(&store.mutex)
	defer sync.mutex_unlock(&store.mutex)
	for index in 0 ..< store.challenge_count {
		if store.challenges[index].id == id {
			return clone_challenge(&store.challenges[index], allocator)
		}
	}
	return {}, false
}

memory_verify_challenge :: proc(
	user_data: rawptr,
	request: ^Challenge_Verify_Request,
) -> auth.Challenge_Status {
	store := cast(^Memory_Store)user_data
	sync.mutex_lock(&store.mutex)
	defer sync.mutex_unlock(&store.mutex)
	for index in 0 ..< store.challenge_count {
		record := &store.challenges[index]
		selector := record.id
		if record.method == .Magic_Link do selector = record.proof_hash
		if selector != request.selector do continue
		result := auth.verify_challenge(
			record,
			request.method,
			request.proof,
			request.hash_key,
			request.now_ms,
		)
		auth.apply_challenge_transition(record, result.transition)
		return result.status
	}
	return .Invalid_Proof
}

memory_insert_session :: proc(user_data: rawptr, record: ^auth.Session) -> bool {
	store := cast(^Memory_Store)user_data
	sync.mutex_lock(&store.mutex)
	defer sync.mutex_unlock(&store.mutex)
	if store.session_count >= len(store.sessions) do return false
	copy, ok := clone_session(record, context.allocator)
	if !ok do return false
	store.sessions[store.session_count] = copy
	store.session_count += 1
	return true
}

memory_load_session :: proc(
	user_data: rawptr,
	id: string,
	allocator: mem.Allocator,
) -> (auth.Session, bool) {
	store := cast(^Memory_Store)user_data
	sync.mutex_lock(&store.mutex)
	defer sync.mutex_unlock(&store.mutex)
	for index in 0 ..< store.session_count {
		if store.sessions[index].id == id {
			return clone_session(&store.sessions[index], allocator)
		}
	}
	return {}, false
}

memory_find_session :: proc(
	user_data: rawptr,
	credential_hashes: []string,
	allocator: mem.Allocator,
) -> (auth.Session, bool) {
	store := cast(^Memory_Store)user_data
	sync.mutex_lock(&store.mutex)
	defer sync.mutex_unlock(&store.mutex)
	for index in 0 ..< store.session_count {
		for candidate in credential_hashes {
			if store.sessions[index].credential_hash == candidate {
				return clone_session(&store.sessions[index], allocator)
			}
		}
	}
	return {}, false
}

memory_revoke_session :: proc(user_data: rawptr, id: string, revoked_at_ms: i64) -> bool {
	store := cast(^Memory_Store)user_data
	sync.mutex_lock(&store.mutex)
	defer sync.mutex_unlock(&store.mutex)
	for index in 0 ..< store.session_count {
		record := &store.sessions[index]
		if record.id != id do continue
		if !record.revoked {
			record.revoked = true
			record.revoked_at_ms = revoked_at_ms
		}
		return true
	}
	return false
}

@(test)
memory_adapter_satisfies_conformance_suite :: proc(t: ^testing.T) {
	store: Memory_Store
	defer destroy_memory_store(&store)
	challenge_store := Challenge_Store{
		user_data = &store,
		insert    = memory_insert_challenge,
		load      = memory_load_challenge,
		verify    = memory_verify_challenge,
	}
	session_store := Session_Store{
		user_data = &store,
		insert    = memory_insert_session,
		load      = memory_load_session,
		find      = memory_find_session,
		revoke    = memory_revoke_session,
	}
	testing.expect(t, assert_challenge_store(t, &challenge_store))
	testing.expect(t, assert_session_store(t, &session_store))
}
