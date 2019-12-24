#!/usr/bin/python

import subprocess
import string
import argparse
from multiprocessing import Pool


def make_proc(binname, dfilter, seen, stdin, perf):
    if perf:
        if stdin:
            return f"echo '{seen}' | perf stat -x, -e instructions:u {binname} > /dev/null"
        return f"perf stat -x, -e instructions:u {binname} '{seen}' > /dev/null"
    if stdin:
        return f"echo '{seen}' | ./patched_qemu -d instrc {dfilter} {binname} > /dev/null"
    return f"./patched_qemu -d instrc {dfilter} {binname} '{seen}' > /dev/null"

def guess(binname, dfilter, length, stdin, perf):
    m = 0
    mi = 0
    for i in range(1, length + 1):
        payload = "a" * i
        print(f'\rTrying {i} ', end="")
        proc = make_proc(binname, dfilter, payload, stdin, perf)
        com = subprocess.run([proc], shell=True, capture_output=True)
        if perf:
            n = int(com.stderr.decode('ascii').strip().split(',')[0])
        else:
            n = int(com.stderr.decode('ascii').strip().split(' ')[-1])
        if n > m:
            print(f'\r[+] Current best {i} ({n})')
            m = n
            mi = i
    print(f"\rGuessed input size: {mi}")

def run(binname, dfilter, length, charset, stdin, r, skip_fast, perf):
    seen = charset[0] * length
    prev = 0

    for i in range(*r):
        m = prev
        mc = charset[0]

        for c in charset:
            seen = seen[:i] + c + seen[i+1:]
            print(f'\r{seen}', end='')
            proc = make_proc(binname, dfilter, seen, stdin, perf)
            com = subprocess.run([proc], shell=True, capture_output=True)
            if perf:
                n = int(com.stderr.decode('ascii').strip().split(',')[0])
            else:
                n = int(com.stderr.decode('ascii').strip().split(' ')[-1])
            if n > m:
                print(f'\r[+] Current best {seen} ({n})')
                m = n
                mc = c
            if n < m and skip_fast:
                break

        seen = seen[:i] + mc + seen[i+1:]
        prev = m

    print(f'\r{seen}')

def main():
    charset = string.ascii_letters + string.digits + '{}()_-.!?,;@/\\'

    parser = argparse.ArgumentParser(description='Instruction counting')
    parser.add_argument('binary', help='Path to the binary')
    parser.add_argument('--length', help='Length of the input to bruteforce, or max length to try if --guess is used.', type=int, required=True)
    parser.add_argument('--dfilter', help='Range over which to count instructions. It should start on a basic block boundary. Supports everything that -dfilter supports in QEMU.', default='')
    parser.add_argument('--stdin', help='Send input in stdin', default=False, action='store_true')
    parser.add_argument('--charset', help='Charset', default=charset, type=str)
    parser.add_argument('--reverse', help='Reverse', default=False, action='store_true')
    parser.add_argument('--skip-fast', help='Skip to the next character as soon as possible.', default=False, action='store_true')
    parser.add_argument('--guess', help='Try to guess the size of the flag', default=False, action='store_true')
    parser.add_argument('--perf', help='Use perf', default=False, action="store_true")

    args = parser.parse_args()

    if args.dfilter != '':
        args.dfilter = '-dfilter ' + args.dfilter

    if not args.guess:
        run(args.binary, args.dfilter, args.length, args.charset, args.stdin,
            (args.length - 1, 0, -1) if args.reverse else (args.length,), args.skip_fast, args.perf)
    else:
        guess(args.binary, args.dfilter, args.length, args.stdin, args.perf)

if __name__ == '__main__':
    main()
