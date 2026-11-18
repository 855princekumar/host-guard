#!/usr/bin/env python3
"""Inside the target, as root: host-guard's own S3 client against the off-site copy.
    s3tool.py head NAME      print the HTTP status of the object
    s3tool.py tamper NAME    flip one byte in the middle of the object (ransomware, insider)"""
import importlib.machinery
import importlib.util
import sys

loader = importlib.machinery.SourceFileLoader('hostguard', '/usr/local/sbin/hostguard')
spec = importlib.util.spec_from_loader('hostguard', loader)
hg = importlib.util.module_from_spec(spec)
loader.exec_module(hg)
action, name = sys.argv[1], sys.argv[2]
key = hg.C['S3_PREFIX'] + name
if action == 'head':
    print(hg.s3('HEAD', key)[0])
elif action == 'tamper':
    st, _, body = hg.s3('GET', key)
    data = bytearray(body)
    data[len(data) // 2] ^= 0xFF
    print(st, hg.s3('PUT', key, bytes(data))[0])
