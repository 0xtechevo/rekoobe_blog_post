#!/usr/bin/env python3

import sys
import json
import r2pipe
import binascii

def main():
    movs = []
    r2 = r2pipe.open(sys.argv[1], flags=['-2'])
    r2.cmd("aaaa")
    functions = json.loads(r2.cmd("aflj"))

    '''Loop over all analyzed functions.'''
    for f in functions:
        r2.cmd("s %s" % f['offset'])

        ## Dissasemble the function.
        disass = json.loads(r2.cmd("pdj"))

        ## Loop over each instruction to find interesting MOV's
        for d in disass:
            if d['bytes'][:2] == "c6" and len(d['bytes']) > 2:

                ## Append the last byte from the mov instruction.
                ## This byte contains the value moved.
                movs.append(d['bytes'][-2:])

    strings = []
    temp = []
    for byte in movs:
        if byte != "00":
            temp.append(binascii.unhexlify(byte))
        else:
            if len(temp) > 0:
                strings.append(b''.join(temp))
            temp = []

    for s in strings:
        print(s.decode())

        
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("./rekoobe_config.py <sample>")
        sys.exit(1)

    main()
