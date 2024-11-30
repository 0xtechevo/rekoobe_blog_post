#!/usr/bin/env python3

import sys
import json
import r2pipe
from arc4 import ARC4

def parse_config(config):
    blocks = config.split("|")
    config = {}
    config['c2'] = blocks[0].strip(";")
    config['flags']   = {}
    for idx, flag in enumerate(blocks[1].rstrip(";").split(";")):
        config['flags']['unknown_' + str(idx)] = int(flag)

    config['hours']   = blocks[2].rstrip(";")
    config['unknown'] = int(blocks[3])
    return config
    
def rc4_decrypt(string, key):
    arc4 = ARC4(key.encode())
    
    clear = arc4.decrypt(string)

    return clear

def main():
    rc4_key = sys.argv[2]
    r = r2pipe.open(sys.argv[1], flags=['-2'])
    r.cmd("aaaa")
    sections = json.loads(r.cmd("iSj"))

    ## Find .data section offset
    for s in sections:
        if s['name'] == ".data":
            paddr = s['paddr']
            size = s['size']

    ## Read .data section data
    with open(sys.argv[1], "rb") as f:
        f.seek(paddr)
        data = f.read(size)
    
    # Extract the streams of bytes of interest
    config = data.split(b"\x00")
    config = list(filter(None, config))
    config = config[:4]


    #config_len = int.from_bytes(config[0], byteorder='little', signed=True)
    config_string = rc4_decrypt(config[1], rc4_key)
    config_proc_flag = config[2][0]
    #config_proc_len = config[2][1]
    config_proc_str = rc4_decrypt(config[3], rc4_key)

    config = parse_config(config_string.decode())
    config['process_change']  = config_proc_flag
    config['process_name'] = config_proc_str.decode()
    print(json.dumps(config,sort_keys=True,indent=4,separators=(',', ': ')))


if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("./rekoobe_config.py <sample> <rc4 key>")
        sys.exit(1)

    main()
