package aws

import "core:strings"
import "core:testing"
import "core:time"

// Reference signatures from botocore 2.34.40 (the signer inside the AWS CLI),
// produced offline for the signing time 2013-05-24T00:00:00Z with synthetic
// credentials. They hold the library to an independent implementation for keys
// that need encoding, both addressing styles, the China partition, a session
// token and a secret longer than one HMAC block.
Reference_Request :: struct {
	method, key, bucket, region: string,
	path_style:                  bool,
	access, secret, token, body: string,
	url, signature:              string,
}

REFERENCE_REQUESTS :: []Reference_Request {
	{"DELETE", "a", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/a", "37c59eb6036e80e5a55f024311e1f010320ac026255681b1294a3be440a355ca"},
	{"PUT", "a", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-a", "https://s3.eu-west-3.amazonaws.com/examplebucket/a", "b7f3777b5aa93936456e6fc2de35d3a91c8d51d48dc55b9989d6021729354e74"},
	{"GET", "a b/c+d", "examplebucket", "us-east-1", false, "ASIALONG", "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL", "tok", "", "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b/c%2Bd", "e86c8a119cef424b568b77322eaf533822b96fb18905b21f3fb39ff84a1b733a"},
	{"PUT", "a b/c+d", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-a b/c+d", "https://examplebucket.s3.us-east-1.amazonaws.com/a%20b/c%2Bd", "5e74468be4821a275302bf0fb997aff82f3bf78ab2fd5ccbf078159068fd0f3e"},
	{"GET", "dir/sub/file.txt", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/dir/sub/file.txt", "ca550d1cb3f06aa4b03d13853a928011b8fb2df04de82497d34705f376ca4cd1"},
	{"HEAD", "dir/sub/file.txt", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/dir/sub/file.txt", "ec2e7016904c685ae83408f90068e78e86e722b47212ec8c1ad0526ba7b03bc7"},
	{"DELETE", "café/日本語.txt", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/caf%C3%A9/%E6%97%A5%E6%9C%AC%E8%AA%9E.txt", "5b8a7fde14f847d1d950bff18c5984b7afa1604e361c8de2858b91ca1236486a"},
	{"PUT", "café/日本語.txt", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-café/日本語.txt", "https://s3.eu-west-3.amazonaws.com/examplebucket/caf%C3%A9/%E6%97%A5%E6%9C%AC%E8%AA%9E.txt", "1bb04e056a6656da3f185f8aac13a056f1ad55d5c762ba712b38b7ac29a1313f"},
	{"PUT", "sp!ec*ial'(chars)", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-sp!ec*ial'(chars)", "https://examplebucket.s3.us-east-1.amazonaws.com/sp%21ec%2Aial%27%28chars%29", "8d4361ad1292165ea3cec90fd284395a5459ae87ac8d04fe0b14b90fe1930269"},
	{"GET", "sp!ec*ial'(chars)", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://s3.eu-west-3.amazonaws.com/examplebucket/sp%21ec%2Aial%27%28chars%29", "a3dc218cd9b01cd8c02ae0c92f234037070b89e524a6c11648f841fda674529f"},
	{"GET", "a~b_c-d.e", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/a~b_c-d.e", "5f2d8c58198f53f564aaec3a2212927580ded162f71d29e58ab0728f361acdb3"},
	{"HEAD", "a~b_c-d.e", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/a~b_c-d.e", "f6af22592d2756217c1925a892949d5a6ba684b96050641b74ebd82aaaa1da95"},
	{"DELETE", "q?x=1&y=2", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/q%3Fx%3D1%26y%3D2", "ae9adb33ce9ba7677464e3ca591c4cd510002d1fa280e7e400450daec100d24e"},
	{"PUT", "q?x=1&y=2", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-q?x=1&y=2", "https://s3.eu-west-3.amazonaws.com/examplebucket/q%3Fx%3D1%26y%3D2", "6fa62794cb137fd4cc87d52eaf20e5c3fa4dc102307e3328b54b70da9e648118"},
	{"PUT", "hash#frag", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-hash#frag", "https://examplebucket.s3.us-east-1.amazonaws.com/hash%23frag", "d6b5c1d64cbb54b16f00317a8aa679812345b3950dab111d340f0f52027d176e"},
	{"GET", "hash#frag", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://s3.eu-west-3.amazonaws.com/examplebucket/hash%23frag", "08d60adb529e1037609ffef52ef4878610ab6c2abb1fa059c399beb1360a4e6c"},
	{"GET", "pct%20already", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/pct%2520already", "05bb4966ec116e80687ceea668c6c222985baa355f74f8c2c2f435521a19e9d0"},
	{"HEAD", "pct%20already", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/pct%2520already", "3e51a386fa427df2a386f324a4253b049daaf99928900f2eddf69a12e40babfd"},
	{"DELETE", "semi;colon:colon@at", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/semi%3Bcolon%3Acolon%40at", "7f45d2c5f147110c9ae5bdc242d4eb3640e3ed8332f502715ee395a71e167760"},
	{"PUT", "semi;colon:colon@at", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-semi;colon:colon@at", "https://s3.eu-west-3.amazonaws.com/examplebucket/semi%3Bcolon%3Acolon%40at", "361a97e369d0f849b99ad8e7109b5af4305d4c2b29148031a99fecf4f20bcf22"},
	{"PUT", "tab\there", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-tab\there", "https://examplebucket.s3.us-east-1.amazonaws.com/tab%09here", "99d487dae6878e1769e46f972bb9d6dd1b336b7c6361af8bed74d8fc6e883255"},
	{"GET", "tab\there", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://s3.eu-west-3.amazonaws.com/examplebucket/tab%09here", "4cb85de5ed90b5f88874225204c453d8a4862dae3aeb3efb47d7b66e5920b866"},
	{"GET", "back\\slash", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/back%5Cslash", "4e7eb7ed13ec7113e80a439690003642ba914cbb0c87c522d8a05762ffeed9a8"},
	{"HEAD", "back\\slash", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/back%5Cslash", "b6a6639f0345726a0eef8e2801c6f1b01d6d24fd22b867a06cdccca8f4cb4efc"},
	{"DELETE", "a/../b", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/a/../b", "570a0bc1a140f62c07b6815f52e7ff75d6bbeeaddc900277ccef98608ced9022"},
	{"PUT", "a/../b", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-a/../b", "https://s3.eu-west-3.amazonaws.com/examplebucket/a/../b", "ba1305b3acfc8ec2abf4699d1406c81b1139b5ddb12c5ec27ab8f0f24a7df843"},
	{"PUT", "/leading", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-/leading", "https://examplebucket.s3.us-east-1.amazonaws.com//leading", "8b82f453246b8897d42ce04dddb7b94675d307901176a72c1d79755021fe0df8"},
	{"GET", "/leading", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://s3.eu-west-3.amazonaws.com/examplebucket//leading", "2de95840655be8f44407a54a7331354171121d2f247ce486b35ea1795fa01b6c"},
	{"GET", "trailing/", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/trailing/", "c4455821d9ac181f8cd91d71dcd67109a657d270736d8949dbfe0034175db4d2"},
	{"HEAD", "trailing/", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/trailing/", "bc823b4e31981df3d4c0f2bc2f4335b5dc8dab39e1fd98eba010e5d54236ec84"},
	{"DELETE", "dou//ble", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/dou//ble", "4277c97bf117c96b0fd43522113ba3a530f11deb7a0138eb77e167376988ac3b"},
	{"PUT", "dou//ble", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-dou//ble", "https://s3.eu-west-3.amazonaws.com/examplebucket/dou//ble", "54766dbd3376e67bb1ac3c29c5b6e4b8627c3f408bff4825387f48c3ed4759c5"},
	{"PUT", "emoji-😀", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "payload-emoji-😀", "https://examplebucket.s3.us-east-1.amazonaws.com/emoji-%F0%9F%98%80", "4d2a4933fd439f9d5d05c5a11449641d45e0b6eb51305ea4bd0c28a9d3f1dc9b"},
	{"GET", "emoji-😀", "examplebucket", "eu-west-3", true, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://s3.eu-west-3.amazonaws.com/examplebucket/emoji-%F0%9F%98%80", "d7622f4e4e3df1876403ac5bce05128760ec6d993afdc52583d055056cbf09dd"},
	{"GET", "[brackets]{braces}|pipe", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/%5Bbrackets%5D%7Bbraces%7D%7Cpipe", "0af81795ccea40ae3f2e547c1102020461a1fd6f6367508935433ce03b508d47"},
	{"HEAD", "[brackets]{braces}|pipe", "examplebucket", "us-east-1", false, "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", "", "https://examplebucket.s3.us-east-1.amazonaws.com/%5Bbrackets%5D%7Bbraces%7D%7Cpipe", "a43a7eb8296e6d5f5bfd94476dd137d9f7c85cbcc44c3accc89bc041593ed04d"},
}

Reference_Presign :: struct {
	key, bucket, region:   string,
	access, secret, token: string,
	expires:               int,
	signature:             string,
}

REFERENCE_PRESIGNS :: []Reference_Presign {
	{"a", "examplebucket", "us-east-1", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", 60, "7ade32780ce1d5a186c508c7a3b6e2ad2ed68bffe2807c303ec78a15868f8562"},
	{"a", "assets.example.com", "eu-west-3", "ASIAEXAMPLE", "secret/with+chars==", "fixture/token+value==", 60, "d3486ce445730ab2d08434fb23f3d737c8716d9be88370318f2a5de9a8e52ab4"},
	{"a b/c+d", "assets.example.com", "eu-west-3", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", 1060, "92e2420294831bf3c1f4f73863d2f8989ac7e6b933ad0347a87610cac9275d6a"},
	{"café/日本語.txt", "examplebucket", "us-east-1", "ASIAEXAMPLE", "secret/with+chars==", "fixture/token+value==", 2060, "8cb3431b38387761df08c562115846ec573ab75cd61037334b4f7f48f79928e6"},
	{"sp!ec*ial'(chars)", "examplebucket", "us-east-1", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", 3060, "e5331250e5c1035516366d7cca7f98e25964bb3e1c19483dda8f9600a10b7d7a"},
	{"sp!ec*ial'(chars)", "assets.example.com", "eu-west-3", "ASIAEXAMPLE", "secret/with+chars==", "fixture/token+value==", 3060, "c8214326d71d52babd70ccdd701d6b5a7b9a504b2b6143111411957b354e121c"},
	{"q?x=1&y=2", "assets.example.com", "eu-west-3", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", 4060, "8de23f6a105dea1ef468fb8a9c234fa2790530b3a86c0db7b4d1fe3b6f95b1bb"},
	{"hash#frag", "examplebucket", "us-east-1", "ASIAEXAMPLE", "secret/with+chars==", "fixture/token+value==", 5060, "cbed087abae171e625b3d499711a9df962b95ef7234306bf748c690ce82a4426"},
	{"pct%20already", "examplebucket", "us-east-1", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", 6060, "e603c0da531fae648185412a0c7881432aeb1eaae2c43513296e756ce1e80f03"},
	{"pct%20already", "assets.example.com", "eu-west-3", "ASIAEXAMPLE", "secret/with+chars==", "fixture/token+value==", 6060, "67270b366ed582e8e7dbc13c6d4dcb8adde87e5c5f251debb2d22bbb9d9f3230"},
	{"a/../b", "assets.example.com", "eu-west-3", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "", 7060, "1c6182c8e515502b76ad7134e25c4cf077c412dab83cfa083031711adb3ebc91"},
	{"emoji-😀", "examplebucket", "us-east-1", "ASIAEXAMPLE", "secret/with+chars==", "fixture/token+value==", 8060, "8e079de10c080db8c532ad173d7f519a8509fd3d4b3b363247371e426e87b7c5"},
}

@(test)
signed_requests_match_the_reference_implementation :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	now := time.unix(1369353600, 0)
	for item in REFERENCE_REQUESTS {
		config := S3_Config {
			bucket     = item.bucket,
			region     = item.region,
			path_style = item.path_style,
		}
		credentials := AWS_Credentials{item.access, item.secret, item.token}
		request: S3_Request
		ok: bool
		switch item.method {
		case "GET":
			request, ok = s3_get_request(config, credentials, item.key, now)
		case "HEAD":
			request, ok = s3_head_request(config, credentials, item.key, now)
		case "DELETE":
			request, ok = s3_delete_request(config, credentials, item.key, now)
		case "PUT":
			request, ok = s3_put_request(config, credentials, item.key, transmute([]u8)item.body, "", now)
		}
		testing.expectf(t, ok, "%s %q", item.method, item.key)
		testing.expect_value(t, request.url, item.url)
		testing.expect_value(t, s3_request_signature(s3_request_header(request, "Authorization")), item.signature)
	}
}

@(test)
presigned_urls_match_the_reference_implementation :: proc(t: ^testing.T) {
	context.allocator = context.temp_allocator
	for item in REFERENCE_PRESIGNS {
		url, ok := s3_download_url(
			{bucket = item.bucket, region = item.region},
			{item.access, item.secret, item.token},
			item.key,
			item.expires,
			time.unix(1369353600, 0),
		)
		testing.expectf(t, ok, "%q", item.key)
		marker :: "&X-Amz-Signature="
		at := strings.index(url, marker)
		testing.expectf(t, at > 0 && url[at + len(marker):] == item.signature, "%q: %s", item.key, url)
	}
}
