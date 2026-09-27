package passwordless_auth

DEFAULT_MAGIC_LINK_TTL_MS  :: i64(900_000)
DEFAULT_CODE_TTL_MS        :: i64(600_000)
DEFAULT_CODE_DIGITS        :: 6
DEFAULT_CODE_MAX_ATTEMPTS  :: i64(5)

Challenge_Method :: enum {
	Magic_Link,
	Code,
}

Challenge_Status :: enum {
	Verified,
	Invalid_Proof,
	Consumed,
	Expired,
	Attempts_Exhausted,
}

Challenge_Transition_Op :: enum {
	No_Transition,
	Consume,
	Record_Failure,
}

Challenge :: struct {
	id:                   string,
	identity:             string,
	method:               Challenge_Method,
	proof_hash:           string,
	created_at_ms:        i64,
	expires_at_ms:        i64,
	consumed_at_ms:       i64,
	consumed:             bool,
	failed_attempt_count: i64,
	max_attempts:         i64,
	metadata:             string,
}

Public_Challenge :: struct {
	id:                   string,
	identity:             string,
	method:               Challenge_Method,
	created_at_ms:        i64,
	expires_at_ms:        i64,
	consumed_at_ms:       i64,
	consumed:             bool,
	failed_attempt_count: i64,
	max_attempts:         i64,
	metadata:             string,
}

Issued_Challenge :: struct {
	record: Challenge,
	proof:  string,
}

Challenge_Transition :: struct {
	op:                   Challenge_Transition_Op,
	consumed_at_ms:       i64,
	failed_attempt_count: i64,
}

Challenge_Result :: struct {
	status:        Challenge_Status,
	challenge:     Public_Challenge,
	has_challenge: bool,
	transition:    Challenge_Transition,
}

Challenge_Issue_Options :: struct {
	id:           string,
	identity:     string,
	method:       Challenge_Method,
	ttl_ms:       i64,
	digits:       int,
	max_attempts: i64,
	metadata:     string,
	hash_key:     string,
	now_ms:       i64,
}

delete_challenge :: proc(challenge: Challenge) {
	delete(challenge.id)
	delete(challenge.identity)
	delete(challenge.proof_hash)
	delete(challenge.metadata)
}

delete_public_challenge :: proc(challenge: Public_Challenge) {
	delete(challenge.id)
	delete(challenge.identity)
	delete(challenge.metadata)
}

delete_issued_challenge :: proc(issued: Issued_Challenge) {
	delete_challenge(issued.record)
	delete(issued.proof)
}

delete_challenge_result :: proc(result: Challenge_Result) {
	if result.has_challenge do delete_public_challenge(result.challenge)
}

public_challenge :: proc(record: ^Challenge) -> Public_Challenge {
	return {
		id                   = owned_string(record.id),
		identity             = owned_string(record.identity),
		method               = record.method,
		created_at_ms        = record.created_at_ms,
		expires_at_ms        = record.expires_at_ms,
		consumed_at_ms       = record.consumed_at_ms,
		consumed             = record.consumed,
		failed_attempt_count = record.failed_attempt_count,
		max_attempts         = record.max_attempts,
		metadata             = owned_string(record.metadata),
	}
}

challenge_result :: proc(status: Challenge_Status) -> Challenge_Result {
	return {
		status = status,
		transition = {op = .No_Transition},
	}
}

challenge_proof :: proc(method: Challenge_Method, digits: int) -> (proof: string, ok: bool) {
	if method == .Code do return random_code_with_digits(digits)
	return random_token()
}

challenge_proof_hash :: proc(
	method: Challenge_Method,
	proof, hash_key: string,
) -> (encoded: string, ok: bool) {
	if method == .Code do return hash_secret_with_key(proof, hash_key)
	return hash_secret(proof)
}

challenge_from_proof :: proc(
	options: Challenge_Issue_Options,
	proof: string,
) -> (record: Challenge, ok: bool) {
	if options.id == "" || options.identity == "" || proof == "" do return
	if options.method == .Code && len(options.hash_key) < 32 do return

	ttl_ms := options.ttl_ms
	if ttl_ms <= 0 {
		ttl_ms = DEFAULT_MAGIC_LINK_TTL_MS
		if options.method == .Code do ttl_ms = DEFAULT_CODE_TTL_MS
	}
	max_attempts := options.max_attempts
	if max_attempts <= 0 {
		max_attempts = 1
		if options.method == .Code do max_attempts = DEFAULT_CODE_MAX_ATTEMPTS
	}

	proof_hash, hash_ok := challenge_proof_hash(options.method, proof, options.hash_key)
	if !hash_ok do return

	id, id_ok := clone_string(options.id)
	if !id_ok {
		delete(proof_hash)
		return
	}
	identity, identity_ok := clone_string(options.identity)
	if !identity_ok {
		delete(id)
		delete(proof_hash)
		return
	}
	metadata, metadata_ok := clone_string(options.metadata)
	if !metadata_ok {
		delete(id)
		delete(identity)
		delete(proof_hash)
		return
	}

	record = {
		id                   = id,
		identity             = identity,
		method               = options.method,
		proof_hash           = proof_hash,
		created_at_ms        = options.now_ms,
		expires_at_ms        = options.now_ms + ttl_ms,
		failed_attempt_count = 0,
		max_attempts         = max_attempts,
		metadata             = metadata,
	}
	return record, true
}

issue_challenge :: proc(options: Challenge_Issue_Options) -> (issued: Issued_Challenge, ok: bool) {
	if options.identity == "" do return
	if options.method == .Code && len(options.hash_key) < 32 do return

	digits := options.digits
	if digits <= 0 do digits = DEFAULT_CODE_DIGITS

	id, id_ok := id_or_random_uuid(options.id)
	if !id_ok do return
	defer delete(id)

	proof, proof_ok := challenge_proof(options.method, digits)
	if !proof_ok do return
	defer delete(proof)

	resolved := options
	resolved.id = id
	record, record_ok := challenge_from_proof(resolved, proof)
	if !record_ok do return

	proof_copy, proof_copy_ok := clone_string(proof)
	if !proof_copy_ok {
		delete_challenge(record)
		return
	}
	return {record = record, proof = proof_copy}, true
}

challenge_selector :: proc(
	method: Challenge_Method,
	id, proof: string,
) -> (selector: string, ok: bool) {
	if method == .Magic_Link do return hash_secret(proof)
	if id == "" do return
	return clone_string(id)
}

verify_challenge :: proc(
	record: ^Challenge,
	method: Challenge_Method,
	proof, hash_key: string,
	now_ms: i64,
) -> Challenge_Result {
	if record == nil || method != record.method do return challenge_result(.Invalid_Proof)
	if record.consumed do return challenge_result(.Consumed)
	if now_ms >= record.expires_at_ms do return challenge_result(.Expired)
	if record.failed_attempt_count >= record.max_attempts {
		return challenge_result(.Attempts_Exhausted)
	}

	matches := matches_secret(record.proof_hash, proof)
	if method == .Code {
		matches = matches_secret_with_key(record.proof_hash, proof, hash_key)
	}
	if matches {
		result := challenge_result(.Verified)
		result.challenge = public_challenge(record)
		result.has_challenge = true
		result.transition = {op = .Consume, consumed_at_ms = now_ms}
		return result
	}

	if method == .Code {
		next_count := record.failed_attempt_count + 1
		status := Challenge_Status.Invalid_Proof
		if next_count >= record.max_attempts do status = .Attempts_Exhausted
		result := challenge_result(status)
		result.transition = {
			op                   = .Record_Failure,
			failed_attempt_count = next_count,
		}
		return result
	}
	return challenge_result(.Invalid_Proof)
}

apply_challenge_transition :: proc(record: ^Challenge, transition: Challenge_Transition) {
	switch transition.op {
	case .Consume:
		record.consumed_at_ms = transition.consumed_at_ms
		record.consumed = true
	case .Record_Failure:
		record.failed_attempt_count = transition.failed_attempt_count
	case .No_Transition:
	}
}
