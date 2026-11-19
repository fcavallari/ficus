#!/usr/bin/env python3
"""lab-net.py: starts the lab's gateway VM and sample VM joined by a private cable.

    python3 lab/lab-net.py --gateway NAME --guest NAME [--guest-window]

The cable is a Unix datagram socket pair (raw Ethernet frames, one per datagram). One end goes to each VM through
`tart run --net-fd`. The two VMs share one private network that exists only inside this process: the host has no address
on it, there is no NAT and no route out. Neither VM gets a shared folder, clipboard or USB.

Prints READY once both `tart run` processes are up. Stops both VMs and exits when either one exits, or on SIGINT or SIGTERM.
Exit 0 after a requested stop, 1 if a VM exited by itself, 2 on a usage error. LAB_TART overrides the `tart` command.
Python 3.9, standard library only.
"""
import argparse
import os
import signal
import socket
import subprocess
import sys
import time

BUFFER_WANTED = 4 << 20
BUFFER_LEAST = 64 << 10

stop_requested = False


def request_stop(_signum, _frame):
    global stop_requested
    stop_requested = True


def raise_buffers(sock):
    """Asks for big buffers so a burst of frames is not dropped; takes the largest size the system accepts."""
    for opt in (socket.SO_SNDBUF, socket.SO_RCVBUF):
        size = BUFFER_WANTED
        while size >= BUFFER_LEAST:
            try:
                sock.setsockopt(socket.SOL_SOCKET, opt, size)
                break
            except OSError:
                size //= 2


def start_vm(tart, name, sock, headless):
    cmd = [tart, "run", "--no-audio", "--no-clipboard", "--no-usb-accessories"]
    if headless:
        cmd.append("--no-graphics")
    cmd.append("--net-fd=%d" % sock.fileno())
    cmd.append(name)
    return subprocess.Popen(cmd, pass_fds=[sock.fileno()], stdin=subprocess.DEVNULL)


def shutdown(tart, names, procs):
    for name in names:
        try:
            subprocess.run([tart, "stop", name], timeout=60, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (subprocess.SubprocessError, OSError):
            pass
    for p in procs:
        if p.poll() is None:
            p.terminate()
    deadline = time.time() + 15
    for p in procs:
        while p.poll() is None and time.time() < deadline:
            time.sleep(0.1)
        if p.poll() is None:
            p.kill()
            p.wait()


def main(argv):
    ap = argparse.ArgumentParser(prog="lab-net.py")
    ap.add_argument("--gateway", required=True)
    ap.add_argument("--guest", required=True)
    ap.add_argument("--guest-window", action="store_true")
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    tart = os.environ.get("LAB_TART", "tart")

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    gw_end, guest_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    raise_buffers(gw_end)
    raise_buffers(guest_end)
    procs = []
    try:
        procs.append(start_vm(tart, args.gateway, gw_end, True))
        procs.append(start_vm(tart, args.guest, guest_end, not args.guest_window))
    except OSError as e:
        print("error: cannot start tart: %s" % e, file=sys.stderr)
        shutdown(tart, [args.gateway, args.guest], procs)
        return 1
    # The children hold their own copies; closing ours lets a dead child show up as a closed cable.
    gw_end.close()
    guest_end.close()

    ready = False
    started = time.time()
    code = 0
    while not stop_requested:
        if any(p.poll() is not None for p in procs):
            code = 1
            break
        if not ready and time.time() - started >= 1.0:
            print("READY", flush=True)
            ready = True
        time.sleep(0.1)
    shutdown(tart, [args.gateway, args.guest], procs)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
