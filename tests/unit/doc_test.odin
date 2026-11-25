package aws

import "core:testing"
import "core:time"

// Unit tests of src/doc.odin: the values the package documentation states.

@(test)
documented_limits_are_the_real_ones :: proc(t: ^testing.T) {
	testing.expect_value(t, CREDENTIAL_REFRESH_MARGIN, 5 * time.Minute)
	testing.expect_value(t, CREDENTIAL_EXPIRY_SKEW, 15 * time.Second)
	testing.expect_value(t, CREDENTIAL_STATIC_REFRESH, 15 * time.Minute)
	testing.expect_value(t, S3_GET_BYTES_MAX, 64 * 1024 * 1024)
	testing.expect_value(t, S3_GET_TIMEOUT_MS, 120000)
}
