#!/usr/bin/python3

import sys
import r2pipe
import argparse
import re

DEBUG = True

def debug(s):
    if DEBUG:
        sys.stderr.write(s + "\n")

class Node:
    def __init__(self, addr, text):
        self.addr = addr
        self.balance = {}
        self.nested = []
        self.text = text
        self.hitcount = 0
        self.succ = set()
        self.pred = set()
        self.seq = []


def load_notes(path):
    if path == '':
        return {}

    ret = {}
    with open(path, "r") as f:
        for l in f.readlines():
            spl = l.rstrip().split(' ')
            addr = int(spl[0], 16)
            # Try to allow \n and "
            txt = " ".join(spl[1:]).replace("\\n", "\\\\n").replace('"', '\\"')

            ret[addr] = txt

        return ret

def dump_graph(bbs, simple, notes, colored_links):
    print('digraph CFG {')
    for b in bbs.values():
        txt = f'\t{b.addr} [fontname="monospace" fontsize=12 shape=box label="'
        txt += f"[address {hex(b.addr)}] [hitcount {b.hitcount}] [instructions {len(b.nested)}]"
        for reg in b.balance:
            txt += f' [{reg} balance {hex(b.balance[reg])}]\\n'
        if len(b.seq):
            txt += f'[seq {" ".join(map(str, b.seq))}]'
        txt += '\\n'

        print(txt, end='')

        for l in b.nested:
            if not simple or "syscall" in l.text or l.addr in notes:
                print(f'{hex(l.addr)}     {l.text}', end="")
                if l.addr in notes:
                    print(f'                // {notes[l.addr]}', end="")
                print('\\l', end='')
        print("\"];")
        for s in b.succ:
            print(f'\t{b.addr} -> {s} [color="{colored_links[b.addr][s]}"];')
    print('}')


def build_bbs(trace, disas):
    bbs = {}

    prev_addr = None
    for addr in trace:
        if addr not in bbs:
            bbs[addr] = Node(addr, f"{disas[addr]}")

        bbs[addr].hitcount += 1

        if prev_addr is not None:
            bbs[prev_addr].succ.add(addr)
            bbs[addr].pred.add(prev_addr)

        prev_addr = addr

    return bbs


def simplify_bbs(trace, bbs):
    simple = {}
    removed = {}

    force_end = set(["ret", "call"])

    for i in range(len(trace)):
        addr = trace[i]
        if addr in removed or addr in simple:
            continue

        bb = [addr]

        if i != len(trace) - 1:

            i += 1
            while i < len(trace) and len(bbs[trace[i]].pred) == 1:
                bb.append(trace[i])
                removed[trace[i]] = addr
                if bbs[trace[i]].text.split(' ')[0] in force_end:
                    break
                i += 1
                if len(bbs[trace[i - 1]].succ) > 1:
                    break
            i -= 1

        node = bbs[bb[0]]
        node.nested.append(Node(bb[0], bbs[bb[0]].text))
        node.hitcount = bbs[bb[0]].hitcount
        for to_put in bb[1:]:
            node.nested.append(bbs[to_put])
        simple[bb[0]] = node
        simple[bb[0]].succ = bbs[bb[-1]].succ
        simple[bb[0]].pred = bbs[bb[0]].pred

    return simple


def make_seq(trace, bbs):
    seq = 0
    for addr in trace:
        if addr not in bbs:
            continue

        bbs[addr].seq.append(seq)
        seq += 1


def make_colors(bbs):
    colored = {}

    jumps = set(["jmp", "jne", "je", "jz", "jnz", "jl", "jb", "jnle", "jo", "jno",
            "js", "jns", "jnae", "jc", "jnb", "jae", "jnc", "jbe", "jna", "ja",
            "jnbe", "jnge", "jge", "jnl", "jle", "jng", "jg", "jp", "jpe",
            "jnp", "jpo", "jcxz", "jecxz"])

    for b in bbs.values():
        last_inst = b.nested[-1]
        colored[b.addr] = {}
        isjmp = False
        if last_inst.text.split(' ')[0] in jumps:
            isjmp = True
            deststr = last_inst.text.split(' ')[-1]
            if deststr[0:2] == "0x":
                colored[b.addr][int(deststr, 16)] = 'green'
            else:
                for succ in b.succ:
                    colored[b.addr][succ] = 'orange'

        for succ in b.succ:
            if succ not in colored[b.addr]:
                if isjmp:
                    colored[b.addr][succ] = 'red'
                else:
                    colored[b.addr][succ] = 'black'

    return colored

def read_trace(fname, disas, rlow, rhigh):
    trace = []
    with open(fname, "r") as f:
        for l in f.readlines():
            spl = l.split('|')
            addr = int(spl[0], 16)
            txt = spl[1].replace('\n', '').replace('*1', '').replace('ptr [', '[')
            if (rlow == 0 and rhigh == 0) or (addr >= rlow and addr <= rhigh):
                trace.append(addr)
                if addr in disas:
                    if disas[addr] != txt:
                        raise("Self modifying code!")
                else:
                    disas[addr] = txt

    return trace

def merge_bbs(bbs, other):
    if bbs is None:
        return other

    for addr in other:
        if addr not in bbs:
            bbs[addr] = other[addr]

    for addr in other:
        for succ in other[addr].succ:
            if succ not in bbs[addr].succ:
                debug(f"{hex(succ)} was not in succs {hex(addr)}")
            bbs[addr].succ.add(succ)
        for pred in other[addr].pred:
            if pred not in bbs[addr].pred:
                debug(f"{hex(pred)} was not in preds {hex(addr)}")
            bbs[addr].pred.add(pred)

    return bbs

def instruction_histogram(bbs):
    hist = {}

    for b in bbs.values():
        for n in b.nested:
            inst = n.text.split(' ')[0]
            if inst not in hist:
                hist[inst] = 0
            hist[inst] += 1

    for k in hist:
        debug(f"{k}: {hist[k]}")


def find_pattern(bb, pattern, i = 0):
    while i <= len(bb.nested) - len(pattern):
        found = True
        matches = []
        for x in range(len(pattern)):
            n = bb.nested[i + x]
            res = re.search(pattern[x], n.text)
            if not res:
                found = False
                matches = None
                break
            matches.append(res)
        if found:
            return i, matches
        i += 1

    return -1, None

def main():
    parser = argparse.ArgumentParser(description='Create CFG from trace')
    parser.add_argument('--simple', help='Simplified CFG', default=False, action='store_true')
    parser.add_argument('--notes', help='Note file', default='')
    parser.add_argument('--range', help='Range to consider', default='0x0-0x0')
    parser.add_argument('--traces', help='Set of instruction traces, separated by spaces', default='')
    parser.add_argument('--seq', help='Display basic block sequence in CFG', default=False, action='store_true')

    args = parser.parse_args()

    rlow = int(args.range.split('-')[0], 16)
    rhigh = int(args.range.split('-')[1], 16)

    disas = {}
    trace = []

    bbs = None
    for x in args.traces.split(' '):
        nt = read_trace(x, disas, rlow, rhigh)
        trace.extend(nt)
        nbbs = build_bbs(nt, disas)
        bbs = merge_bbs(bbs, nbbs)

    simple_bbs = simplify_bbs(trace, bbs)

    notes = load_notes(args.notes)

    if len(args.traces.split(' ')) == 1 and args.seq:
        make_seq(trace, simple_bbs)

    colored_links = make_colors(simple_bbs)
    dump_graph(simple_bbs, args.simple, notes, colored_links)

if __name__ == "__main__":
    main()
