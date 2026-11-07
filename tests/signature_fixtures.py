#!/usr/bin/env python3
"""Independent synthetic SigV4 fixtures: Python standard library only."""
import hashlib
import hmac
from urllib.parse import quote

SECRET="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STAMP="20130524T000000Z"
REGION="us-east-1"
SCOPE="20130524/us-east-1/s3/aws4_request"

def signature(canonical,service="s3"):
    key=("AWS4"+SECRET).encode()
    for part in ("20130524",REGION,service,"aws4_request"):
        key=hmac.new(key,part.encode(),hashlib.sha256).digest()
    scope=SCOPE if service=="s3" else "20130524/us-east-1/"+service+"/aws4_request"
    text="AWS4-HMAC-SHA256\n"+STAMP+"\n"+scope+"\n"+hashlib.sha256(canonical.encode()).hexdigest()
    return hmac.new(key,text.encode(),hashlib.sha256).hexdigest()

host="examplebucket.s3.us-east-1.amazonaws.com"
for method,payload,expected in (
    ("PUT",b"payload","ed63c9a16fbbdfc2127f409b79ffce52deaaea62ab8d39048ca5fc8d256e5b26"),
    ("DELETE",b"","703c365c9e031e61271a08e36dc622e00f12493b12901d9cf725e8f7f01f942b"),
    ("HEAD",b"","fdd51dae18ee3b7b2f9a6fe56ccec529798be849c3d8f94093884fec89aaf4d2"),
):
    digest=hashlib.sha256(payload).hexdigest()
    headers=f"host:{host}\nx-amz-content-sha256:{digest}\nx-amz-date:{STAMP}\nx-amz-security-token:fixture/token+value\n"
    signed="host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    canonical=f"{method}\n/a%20b/c%2Bd\n\n{headers}\n{signed}\n{digest}"
    assert signature(canonical)==expected
    print(method,expected)
query="X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential="+quote("AKIAIOSFODNN7EXAMPLE/"+SCOPE,safe="")+"&X-Amz-Date="+STAMP+"&X-Amz-Expires=86400&X-Amz-SignedHeaders=host"
canonical="GET\n/test.txt\n"+query+"\nhost:examplebucket.s3.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD"
assert signature(canonical)=="aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
print("GET presign",signature(canonical))
headers="content-type:application/json\nhost:email.us-east-1.amazonaws.com\nx-amz-date:"+STAMP+"\n"
payload=b'{"fixture":true}'
canonical="POST\n/v2/email/outbound-emails\n\n"+headers+"\ncontent-type;host;x-amz-date\n"+hashlib.sha256(payload).hexdigest()
print("SES POST",signature(canonical,"ses"))
