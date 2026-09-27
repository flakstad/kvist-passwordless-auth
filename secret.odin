package passwordless_auth

import "core:crypto"
import "core:crypto/hmac"
import "core:crypto/sha2"
import "core:encoding/base64"
import "core:encoding/hex"
import "core:fmt"
import "core:math/rand"
import "core:strings"

SHA256_PREFIX      :: "v1:sha256:"
HMAC_SHA256_PREFIX :: "v1:hmac-sha256:"

clone_string :: proc(value: string) -> (result: string, ok: bool) {
	copy, err := strings.clone(value)
	return copy, err == nil
}

owned_string :: proc(value: string) -> string {
	copy, _ := clone_string(value)
	return copy
}

sha256 :: proc(value: string) -> [32]byte {
	ctx: sha2.Context_256
	digest: [32]byte
	sha2.init_256(&ctx)
	sha2.update(&ctx, transmute([]byte)value)
	sha2.final(&ctx, digest[:])
	return digest
}

hmac_sha256 :: proc(key, value: string) -> [32]byte {
	digest: [32]byte
	hmac.sum(.SHA256, digest[:], transmute([]byte)value, transmute([]byte)key)
	return digest
}

base64url_no_padding :: proc(bytes: []byte) -> (encoded: string, ok: bool) {
	padded, err := base64.encode(bytes, base64.ENC_URL_TABLE)
	if err != nil do return
	defer delete(padded)

	end := len(padded)
	if strings.has_suffix(padded, "==") {
		end -= 2
	} else if strings.has_suffix(padded, "=") {
		end -= 1
	}
	return clone_string(padded[:end])
}

valid_base64url :: proc(value: string) -> bool {
	for character in transmute([]byte)value {
		if !('A' <= character && character <= 'Z') &&
		   !('a' <= character && character <= 'z') &&
		   !('0' <= character && character <= '9') &&
		   character != '-' && character != '_' {
			return false
		}
	}
	return true
}

decode_base64url :: proc(value: string) -> (decoded: []byte, ok: bool) {
	if !valid_base64url(value) || len(value) % 4 == 1 do return

	padded: string
	switch len(value) % 4 {
	case 0:
		padded, ok = clone_string(value)
	case 2:
		padded = fmt.aprintf("%s==", value)
		ok = true
	case 3:
		padded = fmt.aprintf("%s=", value)
		ok = true
	case:
		return
	}
	if !ok do return
	defer delete(padded)

	err: base64.Error
	decoded, err = base64.decode(padded, base64.DEC_URL_TABLE)
	ok = err == nil
	return
}

versioned_hash :: proc(prefix: string, digest: []byte) -> (encoded: string, ok: bool) {
	body, encoded_ok := base64url_no_padding(digest)
	if !encoded_ok do return
	defer delete(body)
	return fmt.aprintf("%s%s", prefix, body), true
}

hash_secret :: proc(value: string) -> (encoded: string, ok: bool) {
	digest := sha256(value)
	return versioned_hash(SHA256_PREFIX, digest[:])
}

hash_secret_with_key :: proc(value, key: string) -> (encoded: string, ok: bool) {
	if len(key) == 0 do return
	digest := hmac_sha256(key, value)
	return versioned_hash(HMAC_SHA256_PREFIX, digest[:])
}

legacy_sha256_hex :: proc(value: string) -> (encoded: string, ok: bool) {
	digest := sha256(value)
	bytes, err := hex.encode(digest[:])
	if err != nil do return
	return transmute(string)bytes, true
}

lowercase_hex :: proc(value: string) -> bool {
	if len(value) != 64 do return false
	for character in transmute([]byte)value {
		if !('0' <= character && character <= '9') &&
		   !('a' <= character && character <= 'f') {
			return false
		}
	}
	return true
}

hash_body :: proc(stored, prefix: string) -> string {
	if strings.has_prefix(stored, prefix) && len(stored) == len(prefix) + 43 {
		return stored[len(prefix):]
	}
	return ""
}

matches_secret :: proc(stored, value: string) -> bool {
	body := hash_body(stored, SHA256_PREFIX)
	if body != "" {
		expected, decoded := decode_base64url(body)
		defer if decoded do delete(expected)
		if decoded {
			actual := sha256(value)
			return crypto.compare_constant_time(expected, actual[:]) == 1
		}
	}

	if lowercase_hex(stored) {
		actual, encoded := legacy_sha256_hex(value)
		defer if encoded do delete(actual)
		return encoded && crypto.compare_constant_time(
			transmute([]byte)stored,
			transmute([]byte)actual,
		) == 1
	}
	return false
}

matches_secret_with_key :: proc(stored, value, key: string) -> bool {
	body := hash_body(stored, HMAC_SHA256_PREFIX)
	if body == "" || key == "" do return false

	expected, decoded := decode_base64url(body)
	defer if decoded do delete(expected)
	if !decoded do return false

	actual := hmac_sha256(key, value)
	return crypto.compare_constant_time(expected, actual[:]) == 1
}

random_token_with_bytes :: proc(byte_count: int) -> (token: string, ok: bool) {
	if byte_count < 16 || byte_count > 1024 do return
	bytes := make([]byte, byte_count)
	defer delete(bytes)
	crypto.rand_bytes(bytes)
	return base64url_no_padding(bytes)
}

random_token :: proc() -> (token: string, ok: bool) {
	return random_token_with_bytes(32)
}

random_code_with_digits :: proc(digits: int) -> (code: string, ok: bool) {
	if digits < 6 || digits > 9 do return
	bound := 1
	for _ in 0 ..< digits do bound *= 10
	value := rand.int_max(bound, crypto.random_generator())
	return fmt.aprintf("%0*d", digits, value), true
}

random_code :: proc() -> (code: string, ok: bool) {
	return random_code_with_digits(6)
}

random_uuid :: proc() -> (id: string, ok: bool) {
	bytes: [16]byte
	crypto.rand_bytes(bytes[:])
	bytes[6] = bytes[6] & 0x0f | 0x40
	bytes[8] = bytes[8] & 0x3f | 0x80

	encoded, err := hex.encode(bytes[:])
	if err != nil do return
	defer delete(encoded)
	text := string(encoded)
	return fmt.aprintf(
		"%s-%s-%s-%s-%s",
		text[:8], text[8:12], text[12:16], text[16:20], text[20:32],
	), true
}

id_or_random_uuid :: proc(id: string) -> (result: string, ok: bool) {
	if id == "" do return random_uuid()
	return clone_string(id)
}
