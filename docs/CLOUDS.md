# Any cloud, a VPS or bare metal

host-guard finds out where it runs by itself and adapts. Nothing to choose at install.

## How it detects the place

Each cloud has a metadata service at `169.254.169.254` that answers only requests
carrying that cloud's own header, so a wrong guess fails fast and cannot be mistaken
for another cloud:

| Cloud | What host-guard asks | Header it must send |
|---|---|---|
| AWS | `/latest/api/token` (IMDSv2), then `/latest/meta-data/instance-type`, `placement/region` | `X-aws-ec2-metadata-token` |
| Google Cloud | `/computeMetadata/v1/instance/machine-type`, `zone` (the answer must carry `Metadata-Flavor: Google`) | `Metadata-Flavor: Google` |
| Azure | `/metadata/instance/compute?api-version=2021-02-01` | `Metadata: true` |
| Oracle Cloud | `/opc/v2/instance/` | `Authorization: Bearer Oracle` |
| anything else | no answer: a VPS or bare metal (`systemd-detect-virt` tells which) | |

The installer asks once and writes the answer to `guard.conf` (`CLOUD=gcp`, for
example). Set `CLOUD=` (empty) to ask at every run, or set it by hand. Detection never
stops anything: when no service answers, the server is treated as a VPS or bare metal.

```bash
sudo hostguard whereami
# Cloud: Google Cloud (e2-medium, asia-south1-a)
# Machine: virtual machine (kvm)
#   - Off-site copies: a Cloud Storage bucket through its S3 interoperability ...
```

## What changes with the place

| | AWS | Google Cloud | Azure | Oracle Cloud | VPS or bare metal |
|---|---|---|---|---|---|
| Off-site copy | S3 (`--s3-bucket`), the instance role, no keys | Cloud Storage through S3 interoperability: `S3_ENDPOINT=https://storage.googleapis.com`, `AWS_REGION=auto`, an HMAC key | `BACKUP_REMOTE=azure` and a container SAS URL | `BACKUP_REMOTE=oci-par` and a bucket pre-authenticated request URL, or the S3 compatibility API | any S3-compatible store (R2, B2, Wasabi, MinIO, Hetzner), Azure Blob or an OCI URL |
| Running cost | estimated from AWS's published prices | set `PRICE_HOUR` (and the other `PRICE_` values) | same | same | same |
| Usual login user | `ubuntu` | your OS Login name (`you_example_com`) | `azureuser` | `ubuntu` | yours |
| Notes | | with OS Login, `--login-user` is the OS Login name | | Oracle's Ubuntu images keep their own rules in `/etc/iptables/rules.v4`; host-guard adds to them | |

Off AWS, the cost section of the daily report says where the server runs and which
setting gives an estimate, instead of guessing with AWS prices.

## Off-site copies, store by store

Every copy is encrypted (gpg, AES-256) before it leaves the server, and every upload is
confirmed: each size and MD5 the store reports (`Content-Length`,
`x-goog-stored-content-length`, `Content-MD5`, `x-goog-hash`) must match, and at least
one must be there. The weekly restore test downloads the newest copy from the store.

**AWS S3** (`guard.conf`): `S3_BUCKET=my-backups`, `AWS_REGION=ap-south-1`. Give the
instance a role allowed `s3:PutObject` and `s3:GetObject` on `my-backups/host-guard/*`.

**Google Cloud Storage**: create an HMAC key for a service account with access to the
bucket, then `S3_BUCKET=my-backups`, `S3_ENDPOINT=https://storage.googleapis.com`,
`AWS_REGION=auto` in `guard.conf` and the key as `AWS_ACCESS_KEY_ID` and
`AWS_SECRET_ACCESS_KEY` in `.env`.

**Azure Blob Storage**: create a container and a SAS for it with read, create and write
(no delete, no list needed), then `BACKUP_REMOTE=azure` in `guard.conf` and the full URL
`https://ACCOUNT.blob.core.windows.net/CONTAINER?sv=...&sig=...` as `BACKUP_REMOTE_URL`
in `.env`. Give it an expiry you will notice; host-guard mails when an upload fails.

**Oracle Cloud Object Storage**: create a pre-authenticated request on the bucket,
"Permit object reads and writes", then `BACKUP_REMOTE=oci-par` and the URL ending in
`/o/` as `BACKUP_REMOTE_URL` in `.env`. Or use the S3 compatibility API with a customer
secret key: `S3_ENDPOINT=https://NAMESPACE.compat.objectstorage.REGION.oraclecloud.com`,
`AWS_REGION=REGION`.

**Any S3-compatible store**: `S3_BUCKET`, `S3_ENDPOINT`, the region it expects, and its
keys in `.env`. A store with a private certificate (self-hosted MinIO): `S3_CA_BUNDLE`.

The SAS and pre-authenticated URLs carry their permission in the URL, so they are
secrets: `.env` only, scrubbed from everything host-guard writes or mails.

## Tested in CI on every change

[ci/clouds/run.sh](../ci/clouds/run.sh): for each cloud, a server whose metadata service
answers like that cloud's ([fake_metadata.py](../ci/clouds/fake_metadata.py): the
documented paths and required headers; the cloud emulators emulate storage, not this
service), and an emulated store for the off-site copy. Each run: `hostguard whereami`
must name the cloud, a real backup goes off-site and is confirmed by checksum, the
restore test downloads, decrypts and unpacks it, and the cost section must not guess.

| Cloud | Store in CI | Checks |
|---|---|---|
| AWS | [Floci](https://floci.io) S3, and [AWS Emulator](https://github.com/aws/aws-emulator) (AWS's own: real SigV4, per-run keys, HTTPS with its own CA) | a wrong secret is refused (403); without the CA, TLS refuses |
| Google Cloud | Floci GCP Cloud Storage (XML API, S3 interoperability) | |
| Azure | [Azurite](https://github.com/Azure/Azurite) (Microsoft's; checks every SAS signature, with a random account key made for each run) | a forged SAS is refused (403) |
| Oracle Cloud | Floci OCI Object Storage, a real pre-authenticated request | |
| VPS or bare metal | no metadata service, local backups | |

Floci's Azure emulator is not used: it checks signatures only against its built-in public
development key, which would have to be written into the repository (and a secret scanner
rightly flags it). Emulators are pinned by image digest. AWS Emulator publishes no image or pinned
package (only LTS/latest), so CI prints its version, commit and package SHA-256 on every
run and runs it with no network and telemetry off.
