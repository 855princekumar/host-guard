#!/usr/bin/env python3
"""From captured mails on stdin, print the subject and the plain-text part of the last mail
whose subject contains the text given as the first argument."""
import email
import sys

want = sys.argv[1]
chunks = sys.stdin.read().split('=== MAIL to ')
for chunk in reversed(chunks):
    body = chunk.split('\n', 1)[1] if '\n' in chunk else ''
    msg = email.message_from_string(body)
    subject = msg.get('Subject', '')
    if want in subject:
        text = next((p.get_payload(decode=True).decode('utf-8', 'replace') for p in msg.walk()
                     if p.get_content_type() == 'text/plain'), '')
        print(f'Subject: {subject}\n\n{text.rstrip()}')
        sys.exit(0)
sys.exit(1)
