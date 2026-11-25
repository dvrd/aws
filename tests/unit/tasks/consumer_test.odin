package main

import "core:encoding/json"
import "core:os"
import "core:slice"
import "core:strings"
import "core:testing"

// Unit tests of cmd/tasks/consumer.odin.

@(test)
the_consumer_vendors_exactly_the_recorded_dependencies :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	data, error := os.read_entire_file(".krs/packages.json", context.allocator)
	if !testing.expect(t, error == nil, "run from the root of the checkout") {
		return
	}
	pins: struct {
		packages: []struct {
			name: string,
		},
	}
	testing.expect(t, json.unmarshal(data, &pins) == nil)
	recorded := make([dynamic]string)
	append(&recorded, "aws")
	for pin in pins.packages {
		append(&recorded, pin.name)
	}
	vendored := slice.clone(CONSUMER_LIBRARIES)
	slice.sort(recorded[:])
	slice.sort(vendored)
	testing.expect_value(t, strings.join(vendored, ","), strings.join(recorded[:], ","))
	testing.expect(t, strings.contains(CONSUMER_SOURCE, `import aws "shared:aws"`))
}
