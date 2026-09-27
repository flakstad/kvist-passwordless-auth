package passwordless_auth

RECOMMENDED_IDENTITY_LIMIT :: i64(5)
RECOMMENDED_CLIENT_LIMIT   :: i64(20)

Issuance_Reason :: enum {
	Allowed,
	Identity_Limit,
	Client_Limit,
	Invalid_Limit,
}

Issuance_Decision :: struct {
	allowed: bool,
	reason:  Issuance_Reason,
}

issuance_decision :: proc(
	identity_count, client_count, identity_limit, client_limit: i64,
) -> Issuance_Decision {
	if identity_limit <= 0 || client_limit <= 0 {
		return {reason = .Invalid_Limit}
	}
	if identity_count >= identity_limit {
		return {reason = .Identity_Limit}
	}
	if client_count >= client_limit {
		return {reason = .Client_Limit}
	}
	return {allowed = true, reason = .Allowed}
}

recommended_issuance_decision :: proc(
	identity_count, client_count: i64,
) -> Issuance_Decision {
	return issuance_decision(
		identity_count,
		client_count,
		RECOMMENDED_IDENTITY_LIMIT,
		RECOMMENDED_CLIENT_LIMIT,
	)
}

