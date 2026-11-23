#!/bin/bash
# check-isolation.sh: proves the sample VM can only reach the lab's gateway.
#
#   lab/check-isolation.sh GUEST_NAME
#
# Runs probes inside the running guest through `tart exec` (LAB_TART overrides the tart command). It exits 0 only if every
# probe passes; otherwise it prints one `FAIL <probe>: <why>` line per failed probe and exits 1. Exit 2 on a usage error.
#
#   address     exactly one non-loopback IPv4 address, in 10.66.0.0/24
#   route       the default route goes through 10.66.0.1, the gateway
#   public-dns  a made-up name resolves to 10.66.0.1
#   public-ip   http://1.1.1.1/ fails or is answered by INetSim
#   lan         http://192.168.1.1/ fails or is answered by INetSim
#   nat         http://192.168.64.1/ (Tart's usual NAT gateway) fails or is answered by INetSim
#   ipv6-address  no IPv6 address but link-local and loopback (the gateway turns IPv6 off)
#   ipv6-public   http://[2606:4700:4700::1111]/ fails or is answered by INetSim
#
# A probe that could not run counts as a failure: it must never read as "blocked". For the HTTP probes, "fails" means
# curl could not connect (exit 7) or timed out (exit 28); any other exit (curl missing, a bad option) is a failure.

export LC_ALL=C
GW=10.66.0.1
TART=${LAB_TART:-tart}
FAILED=0

[ $# -eq 1 ] && [ -n "$1" ] || { echo "usage: check-isolation.sh GUEST_NAME" >&2; exit 2; }
GUEST=$1

fail() { printf 'FAIL %s: %s\n' "$1" "$2"; FAILED=1; }

# probe NAME COMMAND: runs COMMAND in the guest; prints its output. The probe name rides along in the command for the tests.
# `tart exec` starts commands with a minimal PATH (no /sbin), so each probe sets its own.
probe() { "$TART" exec "$GUEST" /bin/sh -c "PATH=/usr/bin:/bin:/usr/sbin:/sbin; $2 # probe:$1" 2>/dev/null; }

# http_probe NAME URL: ok if curl could not connect or timed out, or if the answer came from INetSim.
# -g stops curl from reading the brackets of an IPv6 address as a glob.
http_probe() {
  local out code
  out=$(probe "$1" "curl -g -s -m 5 '$2'; echo EXIT:\$?") || { fail "$1" "probe could not run"; return; }
  code=$(printf '%s\n' "$out" | sed -n 's/.*EXIT:\([0-9][0-9]*\)$/\1/p' | tail -n 1)
  case "$code" in
    '') fail "$1" "probe could not run" ;;
    7|28) ;;
    0) case "$out" in *INetSim*) ;; *) fail "$1" "$2 answered by something other than INetSim" ;; esac ;;
    *) fail "$1" "curl exited $code, which is not a connection failure; the probe did not test the network" ;;
  esac
}

out=$(probe address "ifconfig | awk '/inet /{print \$2}' | grep -v '^127\\.'") || out=
n=$(printf '%s\n' "$out" | grep -c .)
if [ "$n" -ne 1 ]; then fail address "expected one non-loopback address, found $n"
else case "$out" in 10.66.0.*) ;; *) fail address "address $out is not in 10.66.0.0/24" ;; esac; fi

out=$(probe route "route -n get default 2>/dev/null | awk '/gateway:/{print \$2}'") || out=
[ "$(printf '%s' "$out" | tr -d '[:space:]')" = "$GW" ] || fail route "default route is '$(printf '%s' "$out" | tr -d '[:space:]')', not $GW"

out=$(probe public-dns "dscacheutil -q host -a name labcheck-$$.example.invalid") || out=
case "$out" in *"ip_address: $GW"*) ;; *) fail public-dns "a made-up name did not resolve to $GW" ;; esac

http_probe public-ip http://1.1.1.1/
http_probe lan http://192.168.1.1/
http_probe nat http://192.168.64.1/

# IPv6: the address probe above counts IPv4 only. An END line proves the probe ran, since no address (the pass case)
# also makes grep exit 1.
out=$(probe ipv6-address "ifconfig | awk '/inet6 /{print \$2}' | grep -v -i -e '^fe80:' -e '^::1\$'; echo END") || out=
case "$out" in
  END) ;;
  *END) fail ipv6-address "IPv6 address(es) besides link-local: $(printf '%s\n' "$out" | grep -v '^END$' | tr '\n' ' ')" ;;
  *) fail ipv6-address "probe could not run" ;;
esac
http_probe ipv6-public 'http://[2606:4700:4700::1111]/'

if [ "$FAILED" = 0 ]; then echo "isolation ok: $GUEST reaches only the gateway $GW"; fi
exit "$FAILED"
