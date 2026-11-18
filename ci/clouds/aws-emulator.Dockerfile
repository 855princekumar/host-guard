# AWS's official emulator (github.com/aws/aws-emulator). AWS publishes no image and only an
# LTS/latest package, so the version cannot be pinned: ci/clouds/run.sh prints the version,
# release date, commit and the package's SHA-256 on every run. rpm installs it because the
# package's signing key (d940f624) is not in the minimal image. The emulator runs with no
# network at all and telemetry off.
FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal@sha256:c64f3b683d01c1c874831adc6a7b5a2fd6f0f9affd58bc638939a9f46cc03543
ADD https://downloads.aws.com/aws-emulator/packages/aws-emulator/LTS/latest/aws-emulator-x86_64.rpm /tmp/aws-emulator.rpm
RUN sha256sum /tmp/aws-emulator.rpm > /aws-emulator.rpm.sha256 && rpm -i /tmp/aws-emulator.rpm && rm /tmp/aws-emulator.rpm
ENV EMULATOR_TELEMETRY=off
ENTRYPOINT ["aws-emulator", "-b", "127.0.0.1", "-p", "9297"]
