package aws

import "core:fmt"
import "core:os"
import "core:sync"
CREDENTIAL_TEST_KEYS :: [?]string {
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_CREDENTIAL_EXPIRATION",
	"AWS_PROFILE",
	"AWS_SHARED_CREDENTIALS_FILE",
	"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	"AWS_CONTAINER_CREDENTIALS_FULL_URI",
	"AWS_EC2_METADATA_DISABLED",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"AWS_ROLE_ARN",
	"HOME",
}

// Test support shared by every suite compiled into package aws: a synthetic
// environment, an injected clock and a fake metadata service.
Credential_Env_Slot :: struct {
	key, value: string,
	found:      bool,
}

// Environment is process-wide. Hold this across every synthetic test and its
// workers until pop has restored all keys, so parallel tests cannot mix sources.
@(private)
credential_test_env_mutex: sync.Mutex

credential_test_env_push :: proc() -> []Credential_Env_Slot {
	sync.mutex_lock(&credential_test_env_mutex)
	saved := make([]Credential_Env_Slot, len(CREDENTIAL_TEST_KEYS))

	for key, index in CREDENTIAL_TEST_KEYS {
		value, found := os.lookup_env(key, context.allocator)
		saved[index] = {
			key   = key,
			value = value,
			found = found,
		}

		os.unset_env(key)
	}

	return saved
}

credential_test_env_pop :: proc(saved: []Credential_Env_Slot) {
	if saved == nil {
		return
	}

	defer sync.mutex_unlock(&credential_test_env_mutex)

	for slot in saved {
		if slot.found {
			os.set_env(slot.key, slot.value)
		} else {
			os.unset_env(slot.key)
		}

		if slot.value != "" {
			delete(slot.value)
		}
	}

	delete(saved)
}

credential_test_absent :: proc(directory: string) {
	os.set_env("HOME", directory)
	os.set_env("AWS_SHARED_CREDENTIALS_FILE", fmt.tprintf("%s/absent", directory))
	os.set_env("AWS_EC2_METADATA_DISABLED", "true")
}
