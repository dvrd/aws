package aws

import network_client "../surf"
import "core:os"

// Optional per-operation seam for isolated providers and offline tests. Defaults
// use Surf; implementations must preserve its bounded response/trust contract.
HTTP_Execute :: proc(
	method, url: string,
	body: []u8,
	headers: []string,
	ca_file: string,
	allow_http: bool,
	timeout_ms: i64,
	upload_file: ^os.File,
	upload_size: i64,
) -> ([]u8, network_client.Buffered_HTTP_Result)
