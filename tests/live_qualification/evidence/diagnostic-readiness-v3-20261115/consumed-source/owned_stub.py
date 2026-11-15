"""Owned offline capture controls only; never handles credentials or network."""
import os,sys,time
mode=sys.argv[1]
if mode=='ok':print('synthetic')
elif mode=='nonzero':sys.stderr.write('synthetic');raise SystemExit(254)
elif mode=='sleep':time.sleep(10)
elif mode=='limit':sys.stderr.write('x'*20000);sys.stderr.flush();time.sleep(10)
elif mode=='closed':os.close(1);os.close(2);time.sleep(10)
elif mode=='descendant':
 import subprocess
 subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)'])
 raise SystemExit(0)
elif mode=='exception':raise RuntimeError('synthetic offline exception')
else:raise SystemExit(2)
