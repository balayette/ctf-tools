#!/usr/bin/python

import subprocess
import string
import argparse
from multiprocessing import Pool

class Runner:
    NAME = "base"

    def __init__(self, binname, stdin):
        self.binname = binname
        self.stdin = stdin

    def make_proc(self):
        return None

class QemuRunner(Runner):
    NAME = "qemu"

    def __init__(self, binname, stdin, dfilter):
        super().__init__(binname, stdin)
        self.dfilter = dfilter
        if self.dfilter != '':
            self.dfilter = '-dfilter ' + dfilter

    def make_proc(self, payload):
        if self.stdin:
            return f"echo '{payload}' | ./patched_qemu -d instrc {self.dfilter} {self.binname} > /dev/null"
        return f"./patched_qemu -d instrc {self.dfilter} {self.binname} '{payload}' > /dev/null"

    def ins_count(self, stderr):
        return int(stderr.strip().split('\n')[-1].split(' ')[-1])

class PerfRunner(Runner):
    NAME = "perf"

    def make_proc(self, payload):
        if self.stdin:
            return f"echo '{payload}' | perf stat -x, -e instructions:u {self.binname} > /dev/null"
        return f"perf stat -x, -e instructions:u {self.binname} '{payload}' > /dev/null"

    def ins_count(self, stderr):
        for l in stderr.strip().split('\n'):
            if "instructions:u" in l:
                return int(l.split(',')[0])

class PinRunner(Runner):
    NAME = "pin"

    def make_proc(self, payload):
        if self.stdin:
            return f"echo '{payload}' | ./pin -t ./inscount0.so -- {self.binname} > /dev/null"
        return f"./pin -t ./inscount0.so -- {self.binname} '{payload}' > /dev/null"

    def ins_count(self, stderr):
        with open("inscount.out", "r") as f:
            count = int(f.readlines()[0].split(' ')[-1])
            return count

def guess(runner, length, pattern):
    m = 0
    mi = 0
    for i in range(1, length + 1):
        payload = pattern.replace('PATTERN', "a" * i)
        print(f'\rTrying {i} ({payload})', end="")
        proc = runner.make_proc(payload)
        com = subprocess.run([proc], shell=True, capture_output=True)
        n = runner.ins_count(com.stderr.decode('ascii'))
        if n > m:
            print(f'\r[+] Current best {i} ({n} {payload})')
            m = n
            mi = i
    print(f"\rGuessed input size: {mi} {payload}")

def run(runner, length, pattern, charset, r, skip_fast):
    seen = charset[0] * length
    prev = 0

    for i in range(*r):
        m = prev
        mc = charset[0]

        for c in charset:
            seen = seen[:i] + c + seen[i+1:]
            payload = pattern.replace('PATTERN', seen)
            print(f'\r{payload}', end='')
            proc = runner.make_proc(payload)
            com = subprocess.run([proc], shell=True, capture_output=True)
            n = runner.ins_count(com.stderr.decode('ascii'))
            if n > m:
                print(f'\r[+] Current best {payload} ({n})')
                m = n
                mc = c
            if n < m and skip_fast:
                break

        seen = seen[:i] + mc + seen[i+1:]
        prev = m
    print(f'\r{pattern.replace("PATTERN", seen)}')

def main():
    charset = string.ascii_letters + string.digits + '{}()_-.!?,;@/\\'

    parser = argparse.ArgumentParser(description='Instruction counting.')
    parser.add_argument('binary', help='Path to the binary')
    parser.add_argument('--length', help='Length of the input to bruteforce, or max length to try if --guess is used. The length is the length of the payload, EXCLUDING the flag pattern', type=int, required=True)
    parser.add_argument('--dfilter', help='Range over which to count instructions. It should start on a basic block boundary. Supports everything that -dfilter supports in QEMU.', default='')
    parser.add_argument('--stdin', help='Send input on stdin', default=False, action='store_true')
    parser.add_argument('--charset', help='Charset to use', default=charset, type=str)
    parser.add_argument('--reverse', help='Guess from the end', default=False, action='store_true')
    parser.add_argument('--skip-fast', help='Skip to the next character as soon as possible.', default=False, action='store_true')
    parser.add_argument('--guess', help='Try to guess the size of the flag', default=False, action='store_true')
    parser.add_argument('--pattern', help='Pattern of the flag, the "PATTERN" string will be replaced with the flag (CTF{PATTERN}), for example', default="PATTERN", type=str)
    parser.add_argument('--runner',
            help='Choose runners: qemu, perf, pin', default="qemu", type=str)

    args = parser.parse_args()

    runner = None
    if args.runner == "qemu":
        runner = QemuRunner(args.binary, args.stdin, args.dfilter)
    elif args.runner == "perf":
        runner = PerfRunner(args.binary, args.stdin)
    elif args.runner == "pin":
        runner = PinRunner(args.binary, args.stdin)

    if args.guess:
        guess(runner, args.length, args.pattern)
    else:
        r = (args.length - 1, -1, -1) if args.reverse else (args.length,)
        run(runner, args.length, args.pattern, args.charset, r, args.skip_fast)

if __name__ == '__main__':
    main()
