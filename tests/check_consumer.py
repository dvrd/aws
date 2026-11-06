#!/usr/bin/env python3
"""Compile/run an offline AWS consumer from only its documented package closure."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

shared = Path(__file__).resolve().parents[2]
compiler = shutil.which(os.environ.get("ODIN_BIN", "odin"))
if not compiler:
    raise SystemExit("Set ODIN_BIN to a supported Odin compiler executable")
with tempfile.TemporaryDirectory(prefix="aws-consumer-") as temporary:
    root = Path(temporary)
    packages = root / "shared"
    packages.mkdir()
    for name in ("aws", "files", "surf", "http", "ascii", "websocket"):
        shutil.copytree(shared / name, packages / name,
                        ignore=shutil.ignore_patterns(".git", "__pycache__"))
    consumer = root / "consumer"
    consumer.mkdir()
    (consumer / "main.odin").write_text('''package main
import aws "shared:aws"
import files "shared:files"
main :: proc() {
    assert(aws.s3_config_error({bucket="examplebucket", region="us-east-1"}) == "")
    assert(aws.ses_config_valid({region="us-east-1", sender="from@example.test", recipient="to@example.test"}))
    _, error := files.read_limited("", 65536)
    assert(error.kind == .Invalid_Input)
}
''')
    executable = root / "consumer-bin"
    subprocess.run([compiler, "build", str(consumer), "-thread-count:1", "-warnings-as-errors",
                    "-collection:shared=" + str(packages), "-out:" + str(executable)], check=True)
    subprocess.run([str(executable)], check=True)
print("AWS isolated vendored consumer: build and execution passed (offline)")
