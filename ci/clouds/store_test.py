#!/usr/bin/env python3
"""host-guard's own remote() against one emulated store: PUT, HEAD (size), GET (same bytes).
    store_test.py KIND [setting=value ...]     prints one JSON line"""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import sys

os.environ['HOSTGUARD_CONF'] = '/nonexistent'
os.environ['HG_STATE_DIR'] = '/tmp/hg-state'
spec = importlib.util.spec_from_file_location('hostguard', '/usr/local/sbin/hostguard',    # the wheel's copy
                                              loader=importlib.machinery.SourceFileLoader('hostguard', '/usr/local/sbin/hostguard'))
hg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hg)

kind = sys.argv[1]
hg.C['BACKUP_REMOTE'] = kind
for kv in sys.argv[2:]:
    k, v = kv.split('=', 1)
    hg.C[k] = v
data = os.urandom(300_000)
digest = hashlib.sha256(data).hexdigest()
name = f'backup-{kind}-test.tar.gz.gpg'
put = hg.remote('PUT', name, data, digest)[0]
head_st, head_hdr, _ = hg.remote('HEAD', name)
confirmed = head_st == 200 and hg.remote_confirms(head_hdr, data)
get_st, _, body = hg.remote('GET', name)
ok = put in (200, 201) and confirmed and get_st == 200 and body == data
print(json.dumps({'kind': kind, 'put': put, 'head': head_st, 'upload_confirmed': confirmed,
                  'get': get_st, 'same_bytes': body == data, 'ok': ok}))
sys.exit(0 if ok else 1)
