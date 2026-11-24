package main

import "core:encoding/json"
import "core:slice"
import "core:strings"

MAX_BYTES :: 16384

// Every way the runner refuses to continue. The command line reports all of them
// as one fixed guard failure; the names exist for tests and for reading the code.
Failure :: enum {
	None,
	System, // a file, process or allocation call failed
	Invalid_Document, // a required member is missing or has the wrong type
	Duplicate_JSON,
	Invalid_JSON,
	Private_File_Required,
	Metadata_Too_Large,
	Absolute_State_Required,
	Private_Directory_Required,
	Locked,
	Absolute_Binary_Required,
	Executable_Required,
	Scope_Schema_Invalid,
	Scope_Resource_Invalid,
	Scope_Policy_Invalid,
	SES_Policy_Invalid,
	Credential_Policy_Invalid,
	Unbound_Credential_Policy,
	Credential_Policy_Changed,
	Role_Attestation_Invalid,
	Role_Attestation_Required,
	Resources_Not_Ready,
	Verified_SES_Identity_Required,
	Run_Already_Exists,
	Child_Deadline,
	Child_Output_Limit,
	Temporary_Credentials_Required,
	Temporary_Expiration_Required,
	Credentials_Near_Expiry,
	Account_Not_Verified,
	Expected_Role_Not_Verified,
	Campaign_Deadline,
	AWS_CLI_Required,
	Credential_Export_Failed,
	Credential_Export_Invalid,
	Scope_Changed,
	Binary_Changed,
	Native_Result_Invalid,
	Live_Opt_In_Required,
	Run_Binding_Mismatch,
	Run_Requires_Review,
	Plan_Input_Required,
}

// Strict JSON: one value, no duplicate member names, no NaN or Infinity.
decode :: proc(data: []u8) -> (value: json.Value, failure: Failure) {
	if !members_unique(string(data)) {
		return nil, .Duplicate_JSON
	}
	parser := json.make_parser(data, .JSON, true)
	parsed, error := json.parse_value(&parser)
	if error != .None || parser.curr_token.kind != .EOF {
		return nil, .Invalid_JSON
	}
	return parsed, .None
}

decode_object :: proc(data: []u8) -> (object: json.Object, failure: Failure) {
	value := decode(data) or_return
	result, is_object := value.(json.Object)
	if !is_object {
		return nil, .Invalid_Document
	}
	return result, .None
}

// False when an object repeats a member name. Names are compared as written, so a
// name that uses an escape is refused instead of being decoded for the comparison.
members_unique :: proc(text: string) -> bool {
	tokens := json.make_tokenizer(text, .JSON, true)
	// One entry per open object or array; arrays have no member names.
	Scope :: struct {
		names:  map[string]bool,
		object: bool,
	}
	scopes: [dynamic]Scope
	previous: json.Token
	for {
		token, error := json.get_token(&tokens)
		if token.kind == .EOF || error != .None {
			// Malformed text is reported by the parser.
			return true
		}
		#partial switch token.kind {
		case .NaN, .Infinity:
			return false
		case .Open_Brace:
			append(&scopes, Scope{object = true})
		case .Open_Bracket:
			append(&scopes, Scope{})
		case .Close_Brace, .Close_Bracket:
			if len(scopes) > 0 {
				pop(&scopes)
			}
		case .Colon:
			if previous.kind == .String && len(scopes) > 0 && scopes[len(scopes) - 1].object {
				names := &scopes[len(scopes) - 1].names
				if strings.contains_rune(previous.text, '\\') || previous.text in names^ {
					return false
				}
				names[previous.text] = true
			}
		}
		previous = token
	}
}

// Compact JSON with sorted member names, so a document always has the same bytes.
encode :: proc(value: json.Value) -> []u8 {
	builder := strings.builder_make()
	encode_value(&builder, value)
	return builder.buf[:]
}

encode_value :: proc(builder: ^strings.Builder, value: json.Value) {
	switch item in value {
	case json.Null:
		strings.write_string(builder, "null")
	case json.Integer:
		strings.write_i64(builder, item)
	case json.Float:
		strings.write_f64(builder, item, 'g')
	case json.Boolean:
		strings.write_string(builder, "true" if item else "false")
	case json.String:
		encode_text(builder, item)
	case json.Array:
		strings.write_byte(builder, '[')
		for element, index in item {
			if index > 0 {
				strings.write_byte(builder, ',')
			}
			encode_value(builder, element)
		}
		strings.write_byte(builder, ']')
	case json.Object:
		names := make([dynamic]string, 0, len(item))
		for name in item {
			append(&names, name)
		}
		slice.sort(names[:])
		strings.write_byte(builder, '{')
		for name, index in names {
			if index > 0 {
				strings.write_byte(builder, ',')
			}
			encode_text(builder, name)
			strings.write_byte(builder, ':')
			encode_value(builder, item[name])
		}
		strings.write_byte(builder, '}')
	case:
		strings.write_string(builder, "null")
	}
}

encode_text :: proc(builder: ^strings.Builder, text: string) {
	digits := "0123456789abcdef"
	strings.write_byte(builder, '"')
	for index in 0 ..< len(text) {
		character := text[index]
		switch character {
		case '"':
			strings.write_string(builder, "\\\"")
		case '\\':
			strings.write_string(builder, "\\\\")
		case 0 ..< 0x20:
			strings.write_string(builder, "\\u00")
			strings.write_byte(builder, digits[character >> 4])
			strings.write_byte(builder, digits[character & 15])
		case:
			strings.write_byte(builder, character)
		}
	}
	strings.write_byte(builder, '"')
}

text_of :: proc(object: json.Object, name: string) -> (string, bool) {
	value, found := object[name].(json.String)
	return value, found
}

integer_of :: proc(object: json.Object, name: string) -> (i64, bool) {
	value, found := object[name].(json.Integer)
	return value, found
}

boolean_of :: proc(object: json.Object, name: string) -> (bool, bool) {
	value, found := object[name].(json.Boolean)
	return value, found
}

object_of :: proc(object: json.Object, name: string) -> (json.Object, bool) {
	value, found := object[name].(json.Object)
	return value, found
}

is_true :: proc(object: json.Object, name: string) -> bool {
	value, found := boolean_of(object, name)
	return found && value
}

text_is :: proc(object: json.Object, name, expected: string) -> bool {
	value, found := text_of(object, name)
	return found && value == expected
}

integer_is :: proc(object: json.Object, name: string, expected: i64) -> bool {
	value, found := integer_of(object, name)
	return found && value == expected
}

// True when object has exactly these member names.
members_are :: proc(object: json.Object, names: []string) -> bool {
	if len(object) != len(names) {
		return false
	}
	for name in names {
		if name not_in object {
			return false
		}
	}
	return true
}
