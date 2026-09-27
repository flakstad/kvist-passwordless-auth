package passwordless_auth

DEFAULT_SESSION_TTL_MS :: i64(43_200_000)

Session_Status :: enum {
	Active,
	Invalid_Session,
	Revoked_Session,
	Expired_Session,
}

Session :: struct {
	id:              string,
	subject:         string,
	credential_hash: string,
	created_at_ms:   i64,
	expires_at_ms:   i64,
	revoked_at_ms:   i64,
	revoked:         bool,
	metadata:        string,
}

Public_Session :: struct {
	id:            string,
	subject:       string,
	created_at_ms: i64,
	expires_at_ms: i64,
	revoked_at_ms: i64,
	revoked:       bool,
	metadata:      string,
}

Issued_Session :: struct {
	record:     Session,
	credential: string,
}

Session_Result :: struct {
	status:      Session_Status,
	session:     Public_Session,
	has_session: bool,
}

Session_Issue_Options :: struct {
	id:       string,
	subject:  string,
	ttl_ms:   i64,
	metadata: string,
	now_ms:   i64,
}

delete_session :: proc(session: Session, allocator := context.allocator) {
	delete(session.id, allocator)
	delete(session.subject, allocator)
	delete(session.credential_hash, allocator)
	delete(session.metadata, allocator)
}

delete_issued_session :: proc(issued: Issued_Session, allocator := context.allocator) {
	delete_session(issued.record, allocator)
	delete(issued.credential, allocator)
}

session_from_credential :: proc(
	options: Session_Issue_Options,
	credential: string,
	allocator := context.allocator,
) -> (record: Session, ok: bool) {
	if options.id == "" || options.subject == "" || credential == "" do return
	ttl_ms := options.ttl_ms
	if ttl_ms <= 0 do ttl_ms = DEFAULT_SESSION_TTL_MS

	credential_hash, hash_ok := hash_secret(credential, allocator)
	if !hash_ok do return
	id, id_ok := clone_string(options.id, allocator)
	if !id_ok {
		delete(credential_hash, allocator)
		return
	}
	subject, subject_ok := clone_string(options.subject, allocator)
	if !subject_ok {
		delete(id, allocator)
		delete(credential_hash, allocator)
		return
	}
	metadata, metadata_ok := clone_string(options.metadata, allocator)
	if !metadata_ok {
		delete(id, allocator)
		delete(subject, allocator)
		delete(credential_hash, allocator)
		return
	}

	record = {
		id              = id,
		subject         = subject,
		credential_hash = credential_hash,
		created_at_ms   = options.now_ms,
		expires_at_ms   = options.now_ms + ttl_ms,
		metadata        = metadata,
	}
	return record, true
}

issue_session :: proc(
	options: Session_Issue_Options,
	allocator := context.allocator,
) -> (issued: Issued_Session, ok: bool) {
	if options.subject == "" do return

	id, id_ok := id_or_random_uuid(options.id, allocator)
	if !id_ok do return
	defer delete(id, allocator)

	credential, credential_ok := random_token(allocator)
	if !credential_ok do return
	defer delete(credential, allocator)

	resolved := options
	resolved.id = id
	record, record_ok := session_from_credential(resolved, credential, allocator)
	if !record_ok do return

	credential_copy, copy_ok := clone_string(credential, allocator)
	if !copy_ok {
		delete_session(record, allocator)
		return
	}
	return {record = record, credential = credential_copy}, true
}

session_credential_hash :: proc(
	credential: string,
	allocator := context.allocator,
) -> (encoded: string, ok: bool) {
	return hash_secret(credential, allocator)
}

session_credential_hash_candidates :: proc(
	credential: string,
	allocator := context.allocator,
) -> (current, legacy: string, ok: bool) {
	current_ok: bool
	current, current_ok = hash_secret(credential, allocator)
	if !current_ok do return
	legacy_ok: bool
	legacy, legacy_ok = legacy_sha256_hex(credential, allocator)
	if !legacy_ok {
		delete(current, allocator)
		return "", "", false
	}
	return current, legacy, true
}

check_session :: proc(record: ^Session, now_ms: i64) -> Session_Result {
	result := Session_Result{status = .Invalid_Session}
	if record == nil do return result
	if record.revoked {
		result.status = .Revoked_Session
		return result
	}
	if now_ms >= record.expires_at_ms {
		result.status = .Expired_Session
		return result
	}

	result.status = .Active
	result.session = {
		id            = record.id,
		subject       = record.subject,
		created_at_ms = record.created_at_ms,
		expires_at_ms = record.expires_at_ms,
		revoked_at_ms = record.revoked_at_ms,
		revoked       = record.revoked,
		metadata      = record.metadata,
	}
	result.has_session = true
	return result
}

session_active :: proc(record: ^Session, now_ms: i64) -> bool {
	result := check_session(record, now_ms)
	return result.status == .Active
}
