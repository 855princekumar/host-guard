#!/bin/sh
# host-guard: outbound connections to common crypto-mining pool ports are refused,
# from the host and from containers. Idempotent; run at boot after Docker.
PORTS=3333,4444,5555,7777,14433,14444,45560,45700
for chain in OUTPUT DOCKER-USER; do
  iptables -C "$chain" -p tcp -m multiport --dports $PORTS -m comment --comment host-guard-egress -j REJECT 2>/dev/null \
    || iptables -I "$chain" -p tcp -m multiport --dports $PORTS -m comment --comment host-guard-egress -j REJECT 2>/dev/null || true
done
