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
#
# A probe that could not run counts as a failure: it must never read as "blocked".

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

# http_probe NAME URL: ok if curl failed (and said so) or the answer came from INetSim.
http_probe() {
  local out
  out=$(probe "$1" "curl -s -m 5 $2; echo EXIT:\$?") || { fail "$1" "probe could not run"; return; }
  case "$out" in *EXIT:*) ;; *) fail "$1" "probe could not run"; return ;; esac
  case "$out" in
    *EXIT:0*) case "$out" in *INetSim*) ;; *) fail "$1" "$2 answered by something other than INetSim" ;; esac ;;
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

if [ "$FAILED" = 0 ]; then echo "isolation ok: $GUEST reaches only the gateway $GW"; fi
exit "$FAILED"
