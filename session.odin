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

delete_session :: proc(session: Session) {
	delete(session.id)
	delete(session.subject)
	delete(session.credential_hash)
	delete(session.metadata)
}

delete_public_session :: proc(session: Public_Session) {
	delete(session.id)
	delete(session.subject)
	delete(session.metadata)
}

delete_issued_session :: proc(issued: Issued_Session) {
	delete_session(issued.record)
	delete(issued.credential)
}

delete_session_result :: proc(result: Session_Result) {
	if result.has_session do delete_public_session(result.session)
}

session_from_credential :: proc(
	options: Session_Issue_Options,
	credential: string,
) -> (record: Session, ok: bool) {
	if options.id == "" || options.subject == "" || credential == "" do return
	ttl_ms := options.ttl_ms
	if ttl_ms <= 0 do ttl_ms = DEFAULT_SESSION_TTL_MS

	credential_hash, hash_ok := hash_secret(credential)
	if !hash_ok do return
	id, id_ok := clone_string(options.id)
	if !id_ok {
		delete(credential_hash)
		return
	}
	subject, subject_ok := clone_string(options.subject)
	if !subject_ok {
		delete(id)
		delete(credential_hash)
		return
	}
	metadata, metadata_ok := clone_string(options.metadata)
	if !metadata_ok {
		delete(id)
		delete(subject)
		delete(credential_hash)
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

issue_session :: proc(options: Session_Issue_Options) -> (issued: Issued_Session, ok: bool) {
	if options.subject == "" do return

	id, id_ok := id_or_random_uuid(options.id)
	if !id_ok do return
	defer delete(id)

	credential, credential_ok := random_token()
	if !credential_ok do return
	defer delete(credential)

	resolved := options
	resolved.id = id
	record, record_ok := session_from_credential(resolved, credential)
	if !record_ok do return

	credential_copy, copy_ok := clone_string(credential)
	if !copy_ok {
		delete_session(record)
		return
	}
	return {record = record, credential = credential_copy}, true
}

session_credential_hash :: proc(credential: string) -> (encoded: string, ok: bool) {
	return hash_secret(credential)
}

session_credential_hash_candidates :: proc(
	credential: string,
) -> (current, legacy: string, ok: bool) {
	current_ok: bool
	current, current_ok = hash_secret(credential)
	if !current_ok do return
	legacy_ok: bool
	legacy, legacy_ok = legacy_sha256_hex(credential)
	if !legacy_ok {
		delete(current)
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

	id, _ := clone_string(record.id)
	subject, _ := clone_string(record.subject)
	metadata, _ := clone_string(record.metadata)
	result.status = .Active
	result.session = {
		id            = id,
		subject       = subject,
		created_at_ms = record.created_at_ms,
		expires_at_ms = record.expires_at_ms,
		revoked_at_ms = record.revoked_at_ms,
		revoked       = record.revoked,
		metadata      = metadata,
	}
	result.has_session = true
	return result
}

session_active :: proc(record: ^Session, now_ms: i64) -> bool {
	result := check_session(record, now_ms)
	defer delete_session_result(result)
	return result.status == .Active
}
