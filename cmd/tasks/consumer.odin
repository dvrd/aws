package main

import "core:fmt"
import "core:os"

CONSUMER_SOURCE :: `package main
import aws "shared:aws"
main :: proc() {
    assert(aws.s3_config_error({bucket="examplebucket", region="us-east-1"}) == "")
    assert(aws.ses_config_valid({region="us-east-1", sender="from@example.test", recipient="to@example.test"}))
    _, error := aws.read_limited("", 65536)
    assert(error.kind == .Invalid_Input)
}
`

// Builds and runs a program that vendors copies of the library and its
// dependencies, the way a consumer without the shared collection would.
consumer_command :: proc(arguments: []string) -> int {
	work, created := work_directory("consumer")
	if !created {
		return fail("cannot create a work directory")
	}
	defer os.remove_all(work)
	for name in ([]string{"aws", "surf", "websocket", "async"}) {
		source := fmt.aprintf("%s/%s", shared_source(), name)
		if name == "aws" {
			source = fmt.aprintf("%s/src", root_directory())
		}
		if !copy_tree(source, fmt.aprintf("%s/shared/%s", work, name)) {
			return fail("cannot vendor %s from %s", name, source)
		}
	}
	consumer := fmt.aprintf("%s/consumer", work)
	if os.make_directory(consumer) != nil || os.write_entire_file(fmt.aprintf("%s/main.odin", consumer), CONSUMER_SOURCE) != nil {
		return fail("cannot write the consumer")
	}
	binary := fmt.aprintf("%s/consumer.bin", work)
	if code := run(
		{
			compiler(),
			"build",
			consumer,
			"-thread-count:1",
			"-warnings-as-errors",
			fmt.aprintf("-collection:shared=%s/shared", work),
			fmt.aprintf("-out:%s", binary),
		},
	); code != 0 {
		return code
	}
	if code := run({binary}); code != 0 {
		return code
	}
	fmt.println("AWS isolated vendored consumer: build and execution passed (offline)")
	return 0
}
