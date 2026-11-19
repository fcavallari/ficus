# Ficus malware lab

Runs macOS malware in a throwaway Tart VM on a fake internet and records `eslogger` for it. Design:
`docs/superpowers/specs/2026-11-18-malware-lab-vm-design.md`. Plan: `docs/superpowers/plans/2026-11-18-malware-lab-vm.md`.
Authorized use only: your own lab, your own Mac. Never extract or run samples on the host.

## What exists now

| File | What it does |
|---|---|
| `guest-setup.sh` | Run once inside the golden guest: Rosetta, UTC, no sleep, no Spotlight indexing, no auto-updates, fake bait, `/etc/lab-golden-image`. |
| `gateway-setup.sh` | Run once inside the Debian gateway (on Tart's normal NAT, it needs apt): makes it `10.66.0.1/24` with DHCP, DNS for every name, INetSim, redirects and a packet capture. |
| `lab-net.py` | Starts a gateway VM and a sample VM joined by a private socket-pair cable (`tart run --net-fd`). The host is not on that network. |
| `check-isolation.sh` | Proves the sample VM reaches only the gateway. Run before any sample. |

## The images

- `lab-gold`: the golden macOS guest (macOS 26, user `admin`). Configured, shut down, never booted again. `lab-gold-backup` is a spare copy.
- `lab-gw`: the gateway (Debian 13 from `ghcr.io/cirruslabs/debian:latest`, user `admin`). Same rule.
- Every run clones both (`tart clone lab-gold run-X`, `tart clone lab-gw gw-X`) and deletes the clones afterwards. Tart has no snapshot command; a stopped VM is the snapshot.
- To change an image: clone it, boot and edit the clone, shut it down *gracefully* (see below), then swap names with `tart rename`.

## Things learned the hard way (2026-11-19)

- **Shut the gateway down gracefully.** `tart stop` straight after running `gateway-setup.sh` left the new config files at 0 bytes (unflushed). Use `tart exec lab-gw sudo systemctl poweroff` and wait for `tart list` to say `stopped`.
- **`tart exec` starts commands with a minimal PATH** (no `/sbin`). Use full paths or set `PATH=/usr/bin:/bin:/usr/sbin:/sbin`.
- **The gateway must not redirect DHCP.** UDP 67-68 is exempted before the catch-all that sends everything else to INetSim's dummy service.
- **INetSim 1.3.2's DNS service is broken on Debian 13** (it calls `Net::DNS::Nameserver->main_loop`, which no longer exists). dnsmasq answers DNS: `address=/#/10.66.0.1`.
- **A virtiofs shared folder was not writable from the Linux guest**, so there are no shared folders. The harness reads `/var/lib/lab/gateway.pcap` out of the gateway with `tart exec`.
- **Boot times:** a macOS clone is SSH- and agent-ready in about 12 s; the gateway is ready in about 3 s once its network config is static.
- **Capture volume:** `write` plus unmodified `close` were 90% of a 77,000-event, 156 MB capture of 14 seconds of a booting guest. The harness drops `write` and keeps only `close` events with `modified` true.
- **Full Disk Access for `eslogger`:** `sudo eslogger` worked both over SSH and through `tart exec` on the golden image.

## Trying the network by hand

```bash
tart clone lab-gold g1 && tart clone lab-gw w1
python3 lab/lab-net.py --gateway w1 --guest g1 &      # prints READY
lab/check-isolation.sh g1                            # expect: isolation ok
tart exec w1 /bin/sh -c 'sudo cat /var/lib/lab/gateway.pcap' > gateway.pcap
kill %1; tart delete g1; tart delete w1
```

Not built yet: `lab-run.sh` (the one-command run), `fetch-sample.sh`, the summarizer. See the plan, Tasks 2 and 5 to 10.
