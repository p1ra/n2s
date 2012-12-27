#!/usr/bin/python

# Nasm 2 Shellcode
#
# Copyright (C) 2012 p1ra <p1ra@smashthestack.org>
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#

'''
Nasm 2 Shellcode - by p1ra <p1ra@smashthestack.org>

Simple wrapper to compile a nasm assembly files and print the code in escaped format.

Limitations:
    - Currently only supports 32bit mode.
'''

import sys
import getopt
import subprocess
import re

USAGE = "Usage: %s [-a] file" \
        "\n            -a, --print_asm                Print objdump output. " \
        "\n            -c, --clean                    Print escaped shellcode only." % sys.argv[0]

LOG_LEVEL = 1
def log(level,msg):
    if level <= LOG_LEVEL: print msg

def check_tools():
    try:
        subprocess.call(["nasm","-h"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    except:
        log(0,'[-] Error: "nasm" not found.')
        sys.exit(0)

    try:
        subprocess.call(["objdump","-h"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    except:
        log(0,'[-] Error: "objdump" not found.')
        sys.exit(0)

def assemble(fname):
    code = subprocess.call(["nasm","-f","elf32","-o",fname.split(".")[0],fname])
    
    if code != 0:
        log(0,"[-] Assembly error. Exiting...")
        sys.exit(0)

def build_shell(fname):    
    raw_data = subprocess.check_output(["objdump","-d","-M","intel",fname.split(".")[0] + ".o"]);
    index = raw_data.split("0:")[0].rfind('\n');
    data = raw_data[index:]

    log(2,"[+] Assembly code --------")
    log(2,data)

    opcodes = []
    for line in data.split('\n'):
        if len(line) > 0:
            opcodes += re.findall(r'([0-9A-Fa-f][0-9A-Fa-f])\s',line.split(":")[1])

    shellcode = r'\x' + r'\x'.join(opcodes)

    return shellcode

def main():
    global LOG_LEVEL

    try:
        opts, args = getopt.getopt(sys.argv[1:],"ac",["print_asm","clean"])
    except getopt.GetoptError:
        print USAGE
        sys.exit(0)

    if len(args) != 1:
        print USAGE
        sys.exit(0)

    for opt,arg in opts:
        if opt in ("-a","--print_asm"): LOG_LEVEL = 2
        if opt in ("-c","--clean"): LOG_LEVEL = 0

    log(1,"[+] Asm 2 Shellcode - by p1ra.")

    check_tools()

    fname = args[0]

    assemble(fname)

    shellcode = build_shell(fname)

    log(1,"[+] Shellcode --------")
    log(0,shellcode)

main()
