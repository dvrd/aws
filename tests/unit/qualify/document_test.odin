package main

import "core:encoding/json"
import "core:testing"

// Unit tests of cmd/qualify/document.odin: strict decoding and canonical encoding.
@(test)
documents_refuse_duplicate_members_and_non_finite_numbers :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	cases := []struct {
		text:     string,
		expected: Failure,
	} {
		{`{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}`, .None},
		{`{"a":1,"a":2}`, .Duplicate_JSON},
		{`{"a":{"b":1,"b":2}}`, .Duplicate_JSON},
		{`{"a":1,"\u0061":2}`, .Duplicate_JSON},
		{`{"a":NaN}`, .Invalid_JSON},
		{`{"a":1} trailing`, .Invalid_JSON},
		{`{"a":1`, .Invalid_JSON},
	}
	for item in cases {
		text := item.text
		_, failure := decode(transmute([]u8)text)
		testing.expect_value(t, failure, item.expected)
	}
	value, failure := decode_object(transmute([]u8)string(`{"b":[true,null,"q\"\n"],"a":-3}`))
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, string(encode(value)), `{"a":-3,"b":[true,null,"q\"\u000a"]}`)
}

@(test)
documents_encode_sorted_and_escaped :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	value := make(json.Object)
	value["zeta"] = json.Integer(-1)
	value["alpha"] = "line\nquote\"back\\slash\x01"
	middle := make(json.Array)
	append(&middle, true, nil, json.Float(1.5))
	value["mid"] = middle
	inner := make(json.Object)
	inner["b"] = false
	inner["a"] = make(json.Object)
	value["inner"] = inner
	testing.expect_value(
		t,
		string(encode(value)),
		`{"alpha":"line\u000aquote\"back\\slash\u0001","inner":{"a":{},"b":false},"mid":[true,null,1.5],"zeta":-1}`,
	)
	// What encode writes, decode reads back to the same bytes.
	again, failure := decode(encode(value))
	testing.expect_value(t, failure, Failure.None)
	testing.expect_value(t, string(encode(again)), string(encode(value)))
}

@(test)
document_accessors_check_types :: proc(t: ^testing.T) {
	test: Test
	context.allocator = test_begin(&test, t)
	defer test_end(&test)
	object, failure := decode_object(transmute([]u8)string(`{"s":"x","i":3,"b":true,"o":{},"f":1.5}`))
	testing.expect_value(t, failure, Failure.None)
	testing.expect(t, text_is(object, "s", "x") && !text_is(object, "i", "3") && !text_is(object, "missing", ""))
	testing.expect(t, integer_is(object, "i", 3) && !integer_is(object, "f", 1) && !integer_is(object, "s", 0))
	testing.expect(t, is_true(object, "b") && !is_true(object, "s") && !is_true(object, "missing"))
	_, has_object := object_of(object, "o")
	_, string_is_object := object_of(object, "s")
	testing.expect(t, has_object && !string_is_object)
	testing.expect(t, members_are(object, {"s", "i", "b", "o", "f"}))
	testing.expect(t, !members_are(object, {"s", "i", "b", "o"}))
	testing.expect(t, !members_are(object, {"s", "i", "b", "o", "g"}))
	_, not_object := decode_object(transmute([]u8)string(`[1]`))
	testing.expect_value(t, not_object, Failure.Invalid_Document)
}
