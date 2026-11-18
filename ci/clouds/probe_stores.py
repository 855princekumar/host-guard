#!/usr/bin/env python3
"""Exploration: create a bucket or container in each emulator and get a URL or settings that
host-guard's remote() can use. Prints JSON per store. Used by ci/clouds/run.sh."""
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def call(method, url, body=None, headers=None):
    data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
    h = dict(headers or {})
    if isinstance(body, (dict, list)):
        h.setdefault('Content-Type', 'application/json')
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')


def gcp():
    st, text = call('POST', 'http://floci-gcp:4588/storage/v1/b?project=floci-local', {'name': 'hg-backups'})
    return {'store': 'gcs', 'create_bucket': st, 'detail': text[:200]}


# A random account and key made by ci/clouds/run.sh for each run (Azurite takes it through
# AZURITE_ACCOUNTS); no key is written in the repository.
AZ_ACCOUNT = os.environ.get('AZ_ACCOUNT', 'hgtest')
AZ_KEY = os.environ.get('AZ_KEY', '')


def az_sas(container, account=AZ_ACCOUNT, key=AZ_KEY):
    """A service SAS for a container (read, create, write, list), signed with the account key."""
    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    sp, sv, sr, spr = 'rcwl', '2021-08-06', 'c', 'https,http'
    canon = f'/blob/{account}/{container}'
    to_sign = '\n'.join([sp, '', expiry, canon, '', '', spr, sv, sr, '', '', '', '', '', '', ''])
    sig = base64.b64encode(hmac.new(base64.b64decode(key), to_sign.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.urlencode({'sv': sv, 'sp': sp, 'se': expiry, 'sr': sr, 'spr': spr, 'sig': sig})


def account_sas(account=AZ_ACCOUNT, key=AZ_KEY):
    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    sp, ss, srt, spr, sv = 'rwdlac', 'b', 'sco', 'https,http', '2021-08-06'
    to_sign = '\n'.join([account, sp, ss, srt, '', expiry, '', spr, sv, '']) + '\n'
    sig = base64.b64encode(hmac.new(base64.b64decode(key), to_sign.encode(), hashlib.sha256).digest()).decode()
    return urllib.parse.urlencode({'sv': sv, 'ss': ss, 'srt': srt, 'sp': sp, 'se': expiry, 'spr': spr, 'sig': sig})


def azure(host):
    account = AZ_ACCOUNT
    base = f'http://{host}/{account}/hg-backups'
    st, text = call('PUT', base + '?restype=container', b'', {'x-ms-version': '2021-08-06', 'x-ms-date':
                    dt.datetime.now(dt.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')})
    if st == 403:   # Azurite checks signatures: create the container with an account SAS
        st, text = call('PUT', base + '?restype=container&' + account_sas(account), b'', {'x-ms-version': '2021-08-06'})
    return {'store': 'azure', 'host': host, 'create_container': st, 'url': base + '?' + az_sas('hg-backups', account),
            'detail': text[:200]}


OCI_TENANCY = 'ocid1.tenancy.oc1..flocilocaltenancy' + '0' * 40


def oci():
    ns = 'floci-local'
    st, text = call('POST', f'http://floci-oci:4599/n/{ns}/b/', {'name': 'hg-backups', 'compartmentId':
                    OCI_TENANCY})
    st2, text2 = call('POST', f'http://floci-oci:4599/n/{ns}/b/hg-backups/p/', {
        'name': 'host-guard', 'accessType': 'AnyObjectReadWrite', 'timeExpires': '2030-01-01T00:00:00Z'})
    try:
        uri = json.loads(text2).get('accessUri') or json.loads(text2).get('fullPath')
    except ValueError:
        uri = None
    return {'store': 'oci', 'create_bucket': st, 'create_par': st2, 'accessUri': uri, 'detail': (text + ' | ' + text2)[:300]}


if __name__ == '__main__':
    which = sys.argv[1]
    print(json.dumps({'gcp': gcp, 'oci': oci}.get(which, lambda: azure(which))()))
