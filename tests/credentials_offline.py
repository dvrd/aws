#!/usr/bin/env python3
"""Synthetic-only credential chain fixtures; environment and HTTP are isolated."""
import argparse
from pathlib import Path
import os
import subprocess
import tempfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--odin',required=True)
parser.add_argument('--only')
args=parser.parse_args()
root=Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix='aws-credentials-offline-') as temporary:
    directory=Path(temporary)
    binary=directory/'fixture'
    subprocess.run([args.odin,'build',str(root/'testdata/credentials'),'-sanitize:address','-warnings-as-errors','-out:'+str(binary)],check=True)
    profile=directory/'profile'
    partial=directory/'partial'
    token_only=directory/'token-only'
    oversized=directory/'oversize'
    profile.write_text('[default]\naws_access_key_id=fixture-key\naws_secret_access_key=fixture-secret\naws_session_token=fixture-session\n')
    partial.write_text('[default]\naws_access_key_id=fixture-key\n')
    token_only.write_text('[default]\naws_session_token=fixture-session\n')
    oversized.write_bytes(b'x'*(1024*1024))
    modes=['environment','profile','partial-env','partial-profile','token-only-profile','oversize','ecs','imds','disabled','invalid-relative','transport-failure','malformed','invalid-credentials']
    for mode in modes:
        if args.only and args.only!=mode: continue
        # Deliberately do not inherit AWS variables or HOME. No test reads a
        # developer profile, starts an AWS tool, or opens a metadata socket.
        env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(directory),'TMPDIR':str(directory),
             'AWS_SHARED_CREDENTIALS_FILE':str(directory/'absent'),'AWS_EC2_METADATA_DISABLED':'false'}
        if mode=='environment':env.update(AWS_ACCESS_KEY_ID='fixture-key',AWS_SECRET_ACCESS_KEY='fixture-secret',AWS_SESSION_TOKEN='fixture-session')
        if mode=='partial-env':env['AWS_ACCESS_KEY_ID']='fixture-key'
        if mode in ('profile','partial-profile','token-only-profile','oversize'):env['AWS_SHARED_CREDENTIALS_FILE']=str({'profile':profile,'partial-profile':partial,'token-only-profile':token_only,'oversize':oversized}[mode])
        if mode!='imds':env['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI']='/v2/credentials/fixture'
        if mode=='disabled':env.pop('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI');env['AWS_EC2_METADATA_DISABLED']='true'
        if mode=='invalid-relative':env['AWS_CONTAINER_CREDENTIALS_RELATIVE_URI']='//invalid\npath'
        subprocess.run([str(binary),mode],env=env,check=True,timeout=5)
print('Credential resolver fixtures passed; synthetic files/environment and fake HTTP only')
