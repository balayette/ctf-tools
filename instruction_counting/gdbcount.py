#!/usr/bin/python

import subprocess
import string

charset = string.ascii_letters + string.digits + "{}()_-.!?,;@/\\"
seen = "a" * 16

for i in range(16):
    m = 0
    mc = 'a'

    for c in charset:
        seen = seen[:i] + c + seen[i+1:]
        with open("instrcount", 'w') as f:
            f.write("set logging off\n"
                    "set pagination off\n"
                    "set $count=0\n"
                    "b *0x000000000040375D\n"
                    "commands\n"
                    "    set $count++\n"
                    "    continue\n"
                    "end\n"
                    f"r '{seen}'\n"
                    "print $count\n"
                    "quit")


    
        com = subprocess.run([
            "gdb ./binary -x instrcount | tail -n 1"],
            shell=True, capture_output=True)

        n = int(com.stdout.decode("ascii").strip().split(' ')[-1])
        print(f"{seen} => {n} ", end="")
        if n > m:
            print(f"> {m} (New best: {seen})")
            m = n
            mc = c
        else:
            print(f"<= {m}")

    seen = seen[:i] + mc + seen[i+1:]

print(seen)
