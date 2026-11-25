package main

import "core:fmt"
import "core:strings"

odin_binary_sha :: proc(version: string) -> string {
	index := strings.last_index_byte(version, ':')
	if index < 0 {
		return ""
	}
	return strings.trim_space(version[index + 1:])
}

odin_pin_problems :: proc(root: string) -> (problems: []string, pin: string) {
	found := make([dynamic]string)
	pin = strings.trim_space(read_text(fmt.aprintf("%s/ODIN_COMMIT", root)))
	if pin == "" {
		append(&found, "no ODIN_COMMIT: run task odin:pin")
		return found[:], pin
	}

	path, root_code := output({compiler(), "root"})
	fork := strings.trim_space(path)
	if root_code != 0 || fork == "" {
		append(&found, "cannot determine the Odin fork path")
	} else {
		head, code := output({"git", "-C", fork, "rev-parse", "HEAD"})
		if code != 0 {
			append(&found, fmt.aprintf("Odin fork commit unknown, pinned %s", pin))
		} else if strings.trim_space(head) != pin {
			append(&found, fmt.aprintf("Odin fork at %s, pinned %s", strings.trim_space(head), pin))
		}
	}

	version, code := output({compiler(), "version"})
	sha := odin_binary_sha(version)
	if code != 0 || sha == "" {
		append(&found, fmt.aprintf("Odin binary commit unknown, pinned %s: rebuild the compiler", pin))
	} else if !strings.has_prefix(pin, sha) {
		append(&found, fmt.aprintf("Odin binary built from %s, pinned %s: rebuild the compiler", sha, pin))
	}

	if root_code == 0 && fork != "" {
		status, status_code := output({"git", "-C", fork, "status", "--porcelain", "--untracked-files=no"})
		if status_code != 0 {
			append(&found, "cannot check the Odin fork for uncommitted changes")
		} else if strings.trim_space(status) != "" {
			append(&found, "Odin fork has uncommitted changes")
		}
	}
	return found[:], pin
}

odin_command :: proc(arguments: []string) -> int {
	strict := false
	for argument in arguments {
		if argument != "--strict" {
			fail("unknown option: %s", argument)
			return 64
		}
		strict = true
	}

	problems, pin := odin_pin_problems(root_directory())
	if len(problems) == 0 {
		fmt.printf("odin: %s (pinned)\n", pin)
	}
	result := 0
	for problem in problems {
		if strict {
			result = fail("odin: %s", problem)
		} else {
			fmt.printf("odin: warning: %s\n", problem)
		}
	}
	return result
}
