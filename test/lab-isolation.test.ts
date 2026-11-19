import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, test } from 'vitest';

// lab/check-isolation.sh runs probes inside the sample VM through `tart exec`. The stub `tart` finds the probe name in the
// command (`probe:<name>`) and prints what the environment variable STUB_PROBE_<NAME> says, so each probe's answer is a test input.
const SCRIPT = path.resolve(__dirname, '..', 'lab', 'check-isolation.sh');

const STUB = `#!/bin/bash
# args: exec GUEST /bin/sh -c CMD
cmd="\${@: -1}"
name=$(printf '%s' "$cmd" | sed -n 's/.*probe:\\([a-z0-9-]*\\).*/\\1/p')
var="STUB_PROBE_$(printf '%s' "$name" | tr 'a-z-' 'A-Z_')"
if [ "\${STUB_FAIL_EXEC:-}" = "$name" ]; then exit 1; fi
printf '%b' "\${!var}"
`;

const GOOD: Record<string, string> = {
  STUB_PROBE_ADDRESS: '10.66.0.101\\n',
  STUB_PROBE_ROUTE: '10.66.0.1\\n',
  STUB_PROBE_PUBLIC_DNS: 'name: x.example.invalid\\nip_address: 10.66.0.1\\n',
  STUB_PROBE_PUBLIC_IP: '<html>INetSim default HTML page</html>\\nEXIT:0\\n',
  STUB_PROBE_LAN: '\\nEXIT:28\\n',
  STUB_PROBE_NAT: '\\nEXIT:28\\n',
  STUB_PROBE_IPV6_ADDRESS: 'END\\n',
  STUB_PROBE_IPV6_PUBLIC: '\\nEXIT:7\\n',
};

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lab-iso-'));
  fs.writeFileSync(path.join(dir, 'tart'), STUB, { mode: 0o755 });
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function check(over: Record<string, string> = {}, args: string[] = ['g-1']) {
  return spawnSync('/bin/bash', [SCRIPT, ...args], {
    env: { PATH: process.env.PATH ?? '', LAB_TART: path.join(dir, 'tart'), ...GOOD, ...over },
    encoding: 'utf8',
  });
}

describe('lab/check-isolation.sh', () => {
  test('parses under bash', () => {
    expect(spawnSync('/bin/bash', ['-n', SCRIPT]).status).toBe(0);
  });

  test('passes when every probe is blocked or answered by the gateway', () => {
    const r = check();
    expect(r.status, r.stdout + r.stderr).toBe(0);
  });

  test('a page without INetSim from a public address fails public-ip', () => {
    const r = check({ STUB_PROBE_PUBLIC_IP: '<html>Example Domain</html>\\nEXIT:0\\n' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('public-ip');
  });

  test('a real answer from the NAT gateway address fails nat', () => {
    const r = check({ STUB_PROBE_NAT: '<html>router</html>\\nEXIT:0\\n' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('nat');
  });

  test('a second network address fails address', () => {
    const r = check({ STUB_PROBE_ADDRESS: '10.66.0.101\\n192.168.64.5\\n' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('address');
  });

  test('an address outside the lab network fails address', () => {
    expect(check({ STUB_PROBE_ADDRESS: '192.168.64.5\\n' }).status).toBe(1);
  });

  test('a default route through another address fails route', () => {
    const r = check({ STUB_PROBE_ROUTE: '192.168.64.1\\n' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('route');
  });

  test('a name that does not resolve to the gateway fails public-dns', () => {
    const r = check({ STUB_PROBE_PUBLIC_DNS: 'name: x.example.invalid\\nip_address: 93.184.216.34\\n' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('public-dns');
  });

  test('a probe that could not run is a failure, never a pass', () => {
    const r = check({ STUB_FAIL_EXEC: 'lan' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('lan');
  });

  test('reports every failed probe, not only the first', () => {
    const r = check({ STUB_PROBE_NAT: '<html>router</html>\\nEXIT:0\\n', STUB_PROBE_LAN: '<html>router</html>\\nEXIT:0\\n' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('nat');
    expect(r.stdout).toContain('lan');
  });

  test('a curl that could not run is a failure, not a block', () => {
    const r = check({ STUB_PROBE_LAN: '/bin/sh: curl: command not found\\nEXIT:127\\n' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('FAIL lan');
  });

  test('only a refused connection or a timeout counts as blocked', () => {
    expect(check({ STUB_PROBE_LAN: '\\nEXIT:7\\n', STUB_PROBE_NAT: '\\nEXIT:28\\n' }).status).toBe(0);
    const r = check({ STUB_PROBE_NAT: '\\nEXIT:6\\n' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('FAIL nat');
  });

  test('a page whose body has no trailing newline is still read', () => {
    expect(check({ STUB_PROBE_PUBLIC_IP: '<html>INetSim default HTML page</html>EXIT:0\\n' }).status).toBe(0);
  });

  test('a global IPv6 address fails ipv6-address', () => {
    const r = check({ STUB_PROBE_IPV6_ADDRESS: '2001:db8::5\\nEND\\n' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('FAIL ipv6-address');
    expect(r.stdout).toContain('2001:db8::5');
  });

  test('an IPv6 address probe that could not run fails ipv6-address', () => {
    const r = check({ STUB_PROBE_IPV6_ADDRESS: '' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('FAIL ipv6-address');
  });

  test('a real answer over IPv6 fails ipv6-public', () => {
    const r = check({ STUB_PROBE_IPV6_PUBLIC: '<html>Example</html>\\nEXIT:0\\n' });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain('FAIL ipv6-public');
  });

  test('no guest name exits 2', () => {
    expect(check({}, []).status).toBe(2);
  });
});
