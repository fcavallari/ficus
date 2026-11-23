#!/bin/bash
# gateway-setup.sh: turns the Debian VM `lab-gw` into the lab's fake internet. Run it INSIDE the gateway, as root:
#
#   sudo bash gateway-setup.sh [--dry-run]
#
# Needs internet for apt, so run it while the VM is still on Tart's default NAT network. Nothing is switched off or
# restarted that would cut the session; the lab network settings apply at the next boot, on the private cable.
#
# The result: the VM's one network interface is 10.66.0.1/24, with no default route and IP forwarding off. dnsmasq hands out
# addresses (10.66.0.100-200, router and DNS 10.66.0.1) and answers DNS with 10.66.0.1 for every name. INetSim fakes HTTP,
# HTTPS, SMTP, POP3, FTP and more. iptables redirects every TCP and UDP port, and ICMP, to those services, so a sample
# that dials any address reaches INetSim. tcpdump writes /var/lib/lab/gateway.pcap, which the harness reads out with
# `tart exec` before it stops the VM. SSH is turned off. Safe to run twice.

export LC_ALL=C
SCRIPT_VERSION=1
IFACE_GLOB='en*'
GW=10.66.0.1
DRY=0

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

# act DESCRIPTION CMD...: runs CMD, or only prints it under --dry-run. A failure stops the script: a half-built gateway is worse than none.
act() {
  local desc=$1; shift
  if [ "$DRY" = 1 ]; then say "would: $desc"; return 0; fi
  say "do:    $desc"
  "$@" || die "$desc failed"
}

# put PATH: writes stdin to PATH (or reports it under --dry-run).
put() {
  if [ "$DRY" = 1 ]; then say "would: write $1"; cat >/dev/null; return 0; fi
  mkdir -p "$(dirname "$1")" && cat > "$1" || die "could not write $1"
  say "ok:    wrote $1"
}

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if [ "$DRY" = 0 ]; then
  [ "$(uname)" = Linux ] || die "this is not Linux; run it inside the gateway VM (or use --dry-run to look)"
  [ "$(id -u)" = 0 ] || die "run as root (sudo bash gateway-setup.sh)"
  if command -v systemd-detect-virt >/dev/null 2>&1 && [ "$(systemd-detect-virt)" = none ]; then
    die "this is not a virtual machine; refusing to change the network and firewall"
  fi
fi

act "install packages" env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq inetsim dnsmasq tcpdump iptables

# The package makes INetSim's TLS certificates in its postinst; a VM stopped soon after installing lost them (0 bytes).
# Copy the package's own pair back in if they are missing or empty.
if [ "$DRY" = 1 ]; then say "would: make sure INetSim's TLS certificates in /var/lib/inetsim/certs are not empty"
else
  mkdir -p /var/lib/inetsim/certs
  for f in default_key.pem default_cert.pem; do
    if [ ! -s "/var/lib/inetsim/certs/$f" ]; then
      cp "/usr/share/inetsim/data/certs/$f" "/var/lib/inetsim/certs/$f" || die "could not restore $f"
      say "ok:    restored /var/lib/inetsim/certs/$f"
    fi
  done
  chown -R inetsim:inetsim /var/lib/inetsim/certs && chmod 600 /var/lib/inetsim/certs/default_key.pem
fi

put /etc/systemd/network/05-lab.network <<EOF
# Written by gateway-setup.sh: the lab address, no DHCP client, no default route.
[Match]
Name=$IFACE_GLOB

[Network]
Address=$GW/24
DHCP=no
IPv6AcceptRA=no
LinkLocalAddressing=no
EOF

put /etc/sysctl.d/90-lab.conf <<'EOF'
net.ipv4.ip_forward = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

# dnsmasq does DNS as well as DHCP: INetSim 1.3.2's own DNS service is broken on Debian 13 (it calls a Net::DNS method that
# no longer exists), so every name, of any type dnsmasq can answer with an address, resolves to the gateway.
put /etc/dnsmasq.d/lab.conf <<EOF
# Written by gateway-setup.sh: DHCP, and DNS that answers every name with the gateway.
interface=enp0s1
bind-dynamic
no-resolv
no-hosts
address=/#/$GW
dhcp-range=10.66.0.100,10.66.0.200,255.255.255.0,12h
dhcp-option=option:router,$GW
dhcp-option=option:dns-server,$GW
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
EOF

# Keep the package's own file as inetsim.conf.orig, once: only while the file is still the package's (ours has the marker line).
if [ "$DRY" = 0 ] && [ -s /etc/inetsim/inetsim.conf ] && ! grep -q 'Written by gateway-setup.sh' /etc/inetsim/inetsim.conf; then
  cp /etc/inetsim/inetsim.conf /etc/inetsim/inetsim.conf.orig
fi
put /etc/inetsim/inetsim.conf <<EOF
# Written by gateway-setup.sh (original kept as inetsim.conf.orig).
service_bind_address $GW
service_run_as_user inetsim
start_service http
start_service https
start_service smtp
start_service smtps
start_service pop3
start_service pop3s
start_service ftp
start_service ftps
start_service tftp
start_service irc
start_service ntp
start_service ident
start_service syslog
start_service finger
start_service time_tcp
start_service time_udp
start_service daytime_tcp
start_service daytime_udp
start_service dummy_tcp
start_service dummy_udp
EOF

put /usr/local/sbin/lab-redirect.sh <<EOF
#!/bin/sh
# Written by gateway-setup.sh: send everything a sample sends to INetSim.
set -e
iptables -t nat -F PREROUTING
for p in 7 9 13 21 25 37 79 80 110 113 443 465 990 995 6667; do
  iptables -t nat -A PREROUTING -p tcp --dport \$p -j REDIRECT --to-ports \$p
done
# DHCP is for dnsmasq on this machine; the catch-all below must not take it.
iptables -t nat -A PREROUTING -p udp --dport 67:68 -j RETURN
for p in 13 37 53 69 123 514; do
  iptables -t nat -A PREROUTING -p udp --dport \$p -j REDIRECT --to-ports \$p
done
iptables -t nat -A PREROUTING -p icmp -j DNAT --to-destination $GW
iptables -t nat -A PREROUTING -p tcp -j REDIRECT --to-ports 1
iptables -t nat -A PREROUTING -p udp -j REDIRECT --to-ports 1
EOF
act "make the redirect script executable" chmod 755 /usr/local/sbin/lab-redirect.sh

put /etc/systemd/system/lab-redirect.service <<'EOF'
[Unit]
Description=Lab fake internet: redirect everything to INetSim
After=network-pre.target
Before=network.target inetsim.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/lab-redirect.sh

[Install]
WantedBy=multi-user.target
EOF

# The capture stays on the gateway's own disk (a virtiofs shared folder was tried and was not writable from the guest);
# the harness reads /var/lib/lab/gateway.pcap out with `tart exec`. -U writes every packet at once, -Z root keeps tcpdump
# from dropping to a user that cannot write there. Debian 13 keeps tcpdump in /usr/bin.
put /etc/systemd/system/lab-pcap.service <<'EOF'
[Unit]
Description=Lab packet capture
After=network.target

[Service]
StateDirectory=lab
ExecStart=/usr/bin/tcpdump -Z root -i enp0s1 -U -s 0 -w /var/lib/lab/gateway.pcap
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

act "reload systemd" systemctl daemon-reload
act "enable the lab services at boot" systemctl enable lab-redirect.service lab-pcap.service dnsmasq.service inetsim.service
act "turn SSH off" systemctl disable ssh.service
# With one static interface there is nothing to wait for, and the wait would delay the guest agent at every boot.
act "do not wait for the network to come online" systemctl mask systemd-networkd-wait-online.service
act "write the image marker" sh -c "printf 'script_version=%s\nsetup_utc=%s\n' '$SCRIPT_VERSION' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\" > /etc/lab-gateway-image"
# A VM stopped right after this script lost its freshly written files (they were 0 bytes): flush them to disk.
act "flush everything to disk" sync

say "Done. Shut the gateway down with 'sudo systemctl poweroff' (not 'tart stop' straight away); the lab network settings apply at its next boot, on the private cable."
