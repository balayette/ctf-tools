#!/usr/bin/python3

import sys
import r2pipe
import argparse
import re

DEBUG = True


def debug(s):
    if DEBUG:
        sys.stderr.write(s + "\n")


class CFG:
    def __init__(self, bbs):
        self.bbs = bbs


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
    if path == "":
        return {}

    ret = {}
    with open(path, "r") as f:
        for l in f.readlines():
            spl = l.rstrip().split(" ")
            addr = int(spl[0], 16)
            # Try to allow \n and "
            txt = " ".join(spl[1:]).replace("\\n", "\\\\n").replace('"', '\\"')

            ret[addr] = txt

        return ret


class BasicBlock:
    def __init__(self, addr):
        self.addr = addr
        self.hitcount = 0
        self.instrs = []
        self.succ = set()
        self.pred = set()

    def add_instr(self, ins):
        self.instrs.append(ins)

    def dump_asm(self, f, functions):
        f.write(f".L_bb_{hex(self.addr)[2:]}:\n")
        for inst in self.instrs:
            if inst.is_call():
                payload = inst.text.split(" ")[-1]
                try:
                    addr = int(payload, 16)
                except:
                    addr = None

                if addr is not None:
                    if addr in functions:
                        f.write(f"call fun_{hex(addr)[2:]}\n")
                    else:
                        f.write(f"call fun_unkwnown\n")
                else:
                    f.write(f"{inst.text}\n")
            elif inst.is_jump():
                payload = inst.text.split(" ")[-1]
                try:
                    addr = int(payload, 16)
                except:
                    addr = None

                if addr is not None:
                    f.write(f"{inst.text.split(' ')[0]} .L_bb_{hex(addr)[2:]}\n")
                else:
                    f.write(f"{inst.text}\n")
            else:
                f.write(f"{inst.text}\n")


class Function:
    def __init__(self, addr, trace):
        self.addr = addr
        self.trace = trace
        self.bbs = {}

        prev_addr = None
        for t in trace:
            if t.addr not in self.bbs:
                bb = BasicBlock(t.addr)
                bb.add_instr(TraceLine(t.addr, t.text))
                self.bbs[t.addr] = bb

            self.bbs[t.addr].hitcount += 1

            if prev_addr is not None:
                self.bbs[prev_addr].succ.add(t.addr)
                self.bbs[t.addr].pred.add(prev_addr)

            prev_addr = t.addr

    def __str__(self):
        return f"Function {hex(self.addr)} => {hex(self.trace[-1].addr)}\n" + "".join(
            str(self.trace)
        )

    def __repr__(self):
        return self.__str__()

    def asm_label(self):
        return f"fun_{hex(self.addr)[2:]}"

    def _dump_asm(self, f, addr, seen, fs):
        if addr in seen:
            return

        seen.add(addr)

        self.bbs[addr].dump_asm(f, fs)

    def dump_asm(self, f, fs, seen):
        f.write(f".global fun_{hex(self.addr)[2:]}\n")
        f.write(f".type fun_{hex(self.addr)[2:]}, @function\n")
        f.write(f"fun_{hex(self.addr)[2:]}:\n")

        for bb in sorted(self.bbs.keys()):
            self._dump_asm(f, bb, seen, fs)

    def merge(self, other):
        for addr in other.bbs:
            if addr not in self.bbs:
                self.bbs[addr] = other.bbs[addr]

        for addr in other.bbs:
            for succ in other.bbs[addr].succ:
                if succ not in self.bbs[addr].succ:
                    debug(f"{hex(succ)} was not in succs {hex(addr)}")
                self.bbs[addr].succ.add(succ)
            for pred in other.bbs[addr].pred:
                if pred not in self.bbs[addr].pred:
                    debug(f"{hex(pred)} was not in preds {hex(addr)}")
                self.bbs[addr].pred.add(pred)

    def simplify(self):
        while True:
            changed = False

            for bb_addr in self.bbs:
                bb = self.bbs[bb_addr]

                # If we have multiple successors, don't merge any of them
                if len(bb.succ) != 1:
                    continue

                succ_addr = next(iter(bb.succ))
                succ = self.bbs[succ_addr]

                # If our successor has multiple preds, don't merge it
                if len(succ.pred) != 1:
                    continue

                for inst in succ.instrs:
                    bb.add_instr(inst)

                bb.succ.remove(succ_addr)

                for succ_succ_addr in succ.succ:
                    # Add succ's succs to our succs
                    bb.succ.add(succ_succ_addr)
                    # Remove succ from its succs preds
                    self.bbs[succ_succ_addr].pred.remove(succ_addr)
                    # Update the preds of succ's succs
                    self.bbs[succ_succ_addr].pred.add(bb_addr)

                del self.bbs[succ_addr]
                changed = True
                break

            if not changed:
                break

    def dump(self, notes):
        """
        has_note = False
        for bb in self.bbs.values():
            for i in bb.instrs:
                has_note = has_note or i.addr in notes

        if not has_note:
            return
        """

        for bb in self.bbs.values():
            txt = f'\t{bb.addr} [fontname="monospace" fontsize=12 shape=box '
            txt += f'label="[address {hex(bb.addr)}] [hitcount {bb.hitcount}] '
            txt += f"[{len(bb.instrs)} instructions]\\n"
            print(txt, end="")

            for inst in bb.instrs:
                print(f"{hex(inst.addr)}    {inst.text}", end="")
                if inst.addr in notes:
                    print(f"  // {notes[inst.addr]}", end="")
                print("\\l", end="")

            print('"];')
            for s in bb.succ:
                print(f"{bb.addr} -> {s}")


class TraceLine:
    def __init__(self, addr, text):
        self.addr = addr
        self.text = text

    def is_ret(self):
        return "ret" in self.text

    def is_call(self):
        return "call" in self.text

    def is_jump(self):
        jumps = set(
            [
                "jmp",
                "jne",
                "je",
                "jz",
                "jnz",
                "jl",
                "jb",
                "jnle",
                "jo",
                "jno",
                "js",
                "jns",
                "jnae",
                "jc",
                "jnb",
                "jae",
                "jnc",
                "jbe",
                "jna",
                "ja",
                "jnbe",
                "jnge",
                "jge",
                "jnl",
                "jle",
                "jng",
                "jg",
                "jp",
                "jpe",
                "jnp",
                "jpo",
                "jcxz",
                "jecxz",
            ]
        )

        return any(j in self.text for j in jumps)

    def __str__(self):
        return f"{hex(self.addr)}|{self.text}\n"

    def __repr__(self):
        return self.__str__()


def _functions_from_trace(trace, functions):
    lines = []
    i = 0
    while i < len(trace):
        l = trace[i]
        lines.append(l)

        if l.is_call():
            debug(f"Call at {hex(l.addr)}")
            i += _functions_from_trace(trace[i + 1 :], functions) + 1
        else:
            i += 1
            if l.is_ret():
                debug(f"Returning at {hex(l.addr)}")
                break

    if len(trace) == 0:
        return 0

    f = Function(trace[0].addr, lines)

    functions.append(f)

    return i


def functions_from_trace(fname, disas):
    with open(fname, "r") as f:
        lines = f.readlines()
        trace = []
        for l in lines:
            spl = l.split("|")
            addr = int(spl[0], 16)
            txt = spl[1].replace("\n", "")
            # gcc and clang disagree with pintool
            if txt == "nop edx, edi":
                txt = "endbr64"
            elif txt == "nop dword ptr [rax], eax":
                txt = "nop dword ptr [rax]"
            trace.append(TraceLine(addr, txt))
            if addr in disas and disas[addr] != txt:
                raise "Self modifying code!"
            else:
                disas[addr] = txt

        functions = []
        _functions_from_trace(trace, functions)

        return functions


def group_functions(functions):
    fd = {}
    for f in functions:
        if f.addr not in fd:
            fd[f.addr] = f
            continue

        fd[f.addr].merge(f)

    return fd


def to_asm(fs, fname):
    with open(fname, "w") as f:
        f.write(".intel_syntax noprefix\n")
        # needed for calls that go to libc, for example
        f.write(".global fun_unknown\n")
        f.write(".type fun_unknown, @function\n")
        f.write("fun_unknown:\n")
        f.write("ret\n")

        seen = set()

        for fun in fs.values():
            fun.dump_asm(f, fs.keys(), seen)


def main():
    parser = argparse.ArgumentParser(description="Create CFG from trace")
    parser.add_argument(
        "--simple", help="Simplified CFG", default=False, action="store_true"
    )
    parser.add_argument("--notes", help="Note file", default="")
    parser.add_argument("--range", help="Range to consider", default="0x0-0x0")
    parser.add_argument(
        "--traces", help="Set of instruction traces, separated by spaces", default=""
    )
    parser.add_argument(
        "--seq",
        help="Display basic block sequence in CFG",
        default=False,
        action="store_true",
    )

    args = parser.parse_args()

    rlow = int(args.range.split("-")[0], 16)
    rhigh = int(args.range.split("-")[1], 16)

    disas = {}
    trace = []

    bbs = None
    x = args.traces.split(" ")[0]
    functions = functions_from_trace(x, disas)
    fd = group_functions(functions)

    for f in fd.values():
        f.simplify()

    notes = load_notes(args.notes)

    print("digraph CFG {")
    print('graph [splines=ortho, nodesep=0.8]')
    for f in fd.values():
        f.dump(notes)
    print("}")

    # Doesn't work
    # to_asm(fd, "out.S")

if __name__ == "__main__":
    main()
