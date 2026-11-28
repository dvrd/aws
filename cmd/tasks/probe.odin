package main

import "core:fmt"
import "core:os"

QUALIFICATION_PROBE :: "tests/qualification/probe"

// Builds the live qualification probe against the staged collection into
// build/probe, the binary "task qualify -- plan --binary" takes.
probe_command :: proc(arguments: []string) -> int {
	for argument in arguments {
		return fail("unknown option: %s", argument)
	}
	work, created := work_directory("probe")
	if !created {
		return fail("cannot create a work directory")
	}
	defer os.remove_all(work)
	shared, staged := stage_collection(work)
	if !staged {
		return fail("cannot stage the shared collection")
	}
	root := root_directory()
	if !directory_ensure(fmt.aprintf("%s/build", root)) {
		return fail("cannot create build/")
	}
	output := fmt.aprintf("%s/build/probe", root)
	command := []string {
		compiler(),
		"build",
		QUALIFICATION_PROBE,
		fmt.aprintf("-collection:shared=%s", shared),
		"-vet",
		VET_PACKAGES,
		"-warnings-as-errors",
		fmt.aprintf("-out:%s", output),
	}
	if code := run(command, timeout = BUILD_TIMEOUT); code != 0 {
		return code
	}
	fmt.println(output)
	return 0
}
