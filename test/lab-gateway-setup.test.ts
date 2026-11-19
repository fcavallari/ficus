import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

// lab/gateway-setup.sh builds the fake-internet gateway inside a Debian VM. It must never touch the host Mac, so these
// tests only parse it, read --help, use --dry-run, and check that it refuses to run for real here.
const SCRIPT = path.resolve(__dirname, '..', 'lab', 'gateway-setup.sh');
const run = (...args: string[]) => spawnSync('/bin/bash', [SCRIPT, ...args], { encoding: 'utf8', env: { PATH: process.env.PATH ?? '' } });

describe('lab/gateway-setup.sh', () => {
  test('parses under bash', () => {
    expect(spawnSync('/bin/bash', ['-n', SCRIPT]).status).toBe(0);
  });

  test('--help exits 0 and describes the gateway', () => {
    const r = run('--help');
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('10.66.0.1/24');
  });

  test('an unknown argument exits 2', () => {
    expect(run('--nope').status).toBe(2);
  });

  test('--dry-run lists every file and step and changes nothing', () => {
    const r = run('--dry-run');
    expect(r.status, r.stderr).toBe(0);
    for (const want of [
      'install packages',
      '/etc/systemd/network/05-lab.network',
      '/etc/dnsmasq.d/lab.conf',
      '/etc/inetsim/inetsim.conf',
      '/usr/local/sbin/lab-redirect.sh',
      '/etc/systemd/system/lab-pcap.service',
      'turn SSH off',
      'do not wait for the network to come online',
      'flush everything to disk',
    ]) expect(r.stdout, want).toContain(want);
  });

  test('the written configuration keeps DHCP away from the catch-all and answers every name with the gateway', () => {
    const src = fs.readFileSync(SCRIPT, 'utf8');
    const dhcp = src.indexOf('--dport 67:68 -j RETURN');
    const catchAll = src.indexOf('-p udp -j REDIRECT --to-ports 1');
    expect(dhcp).toBeGreaterThan(-1);
    expect(dhcp).toBeLessThan(catchAll);
    expect(src).toContain('address=/#/$GW');
    expect(src).not.toMatch(/^start_service dns$/m); // INetSim's own DNS service is broken on Debian 13
    expect(src).toContain('/var/lib/inetsim/certs');
  });

  test('refuses to run for real anywhere but a Linux VM, as root', () => {
    // With no `uname` on the PATH the script cannot tell it is on Linux, so it refuses on every machine, including a Linux CI box
    // that is a VM and runs as root, where it would otherwise go on to install packages and rewrite the network settings.
    const r = spawnSync('/bin/bash', [SCRIPT], { encoding: 'utf8', env: { PATH: '/nonexistent' } });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('not Linux');
  });
});
