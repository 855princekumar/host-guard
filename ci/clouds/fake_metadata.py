#!/usr/bin/env python3
"""A metadata service at 169.254.169.254 that answers like one cloud's (PROVIDER=aws|gcp|azure|oci),
with that cloud's documented paths and required request header; anything else is refused, as
the real services do. The cloud emulators (Floci, Azurite) emulate storage, not this service."""
import http.server
import json
import os

PROVIDER = os.environ['PROVIDER']
TOKEN = 'fake-imdsv2-token'


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body, headers=None):
        data = body.encode()
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_PUT(self):
        if PROVIDER == 'aws' and self.path == '/latest/api/token' and self.headers.get('X-aws-ec2-metadata-token-ttl-seconds'):
            return self.reply(200, TOKEN)
        self.reply(405, 'no')

    def do_GET(self):
        p, h = self.path, self.headers
        if PROVIDER == 'aws' and h.get('X-aws-ec2-metadata-token') == TOKEN:
            table = {'/latest/meta-data/instance-type': 't3.small', '/latest/meta-data/placement/region': 'ap-south-1',
                     '/latest/meta-data/instance-id': 'i-0123456789abcdef0'}
            if p in table:
                return self.reply(200, table[p])
        if PROVIDER == 'gcp' and h.get('Metadata-Flavor') == 'Google':
            table = {'/computeMetadata/v1/instance/machine-type': 'projects/123/machineTypes/e2-medium',
                     '/computeMetadata/v1/instance/zone': 'projects/123/zones/asia-south1-a'}
            if p in table:
                return self.reply(200, table[p], {'Metadata-Flavor': 'Google'})
        if PROVIDER == 'azure' and h.get('Metadata') == 'true' and p.startswith('/metadata/instance/compute?api-version='):
            return self.reply(200, json.dumps({'vmSize': 'Standard_B2s', 'location': 'centralindia'}),
                              {'Content-Type': 'application/json'})
        if PROVIDER == 'oci' and h.get('Authorization') == 'Bearer Oracle' and p == '/opc/v2/instance/':
            return self.reply(200, json.dumps({'shape': 'VM.Standard.E4.Flex', 'canonicalRegionName': 'ap-mumbai-1'}),
                              {'Content-Type': 'application/json'})
        self.reply(404 if PROVIDER != 'aws' else 401, 'not found')


http.server.ThreadingHTTPServer(('0.0.0.0', 80), H).serve_forever()
