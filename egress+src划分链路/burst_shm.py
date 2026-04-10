#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import mmap
import os
import re
import socket
import struct
import sys
import time
from typing import List, Tuple

DEV_RE_TMPL = r"^veth([0-9a-f]+)\.0\.{sid}$"

IF_NAMESIZE = 16
LINK_SHM_MAGIC = 0x4C534442
LINK_SHM_VERSION = 2
LINK_SHM_CAP = 65536
DEFAULT_SHM_NAME = "lsdb_link_updates"

NATIVE = "<" if sys.byteorder == "little" else ">"
HEADER_FMT = f"{NATIVE}IIIIQQQQQ"
SLOT_FMT = f"{NATIVE}{IF_NAMESIZE}sIIIIIIQ"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
SLOT_SIZE = struct.calcsize(SLOT_FMT)
REGION_SIZE = HEADER_SIZE + LINK_SHM_CAP * SLOT_SIZE

WRITE_POS_OFF = struct.calcsize(f"{NATIVE}IIII")
READ_POS_OFF = WRITE_POS_OFF + 8
PROD_DROPS_OFF = READ_POS_OFF + 8


def list_devs(sid: int) -> List[Tuple[str, int]]:
    pat = re.compile(DEV_RE_TMPL.format(sid=sid))
    out: List[Tuple[str, int]] = []
    for name in os.listdir("/sys/class/net"):
        m = pat.match(name)
        if not m:
            continue
        try:
            node_id = int(m.group(1), 16)
        except ValueError:
            continue
        if 1 <= node_id <= 254:
            out.append((name, node_id))
    out.sort(key=lambda x: x[1])
    return out


def resolve_shm_path(name: str) -> str:
    if not name:
        name = DEFAULT_SHM_NAME
    if name.startswith("/"):
        return name
    return f"/dev/shm/{name}"


def ip_to_src_ip_be(ip: str) -> int:
    return int.from_bytes(socket.inet_aton(ip), sys.byteorder)


def init_region(mm: mmap.mmap) -> None:
    magic, version, capacity, slot_size, *_ = struct.unpack_from(HEADER_FMT, mm, 0)
    if (
        magic == LINK_SHM_MAGIC
        and version == LINK_SHM_VERSION
        and capacity == LINK_SHM_CAP
        and slot_size == SLOT_SIZE
    ):
        return

    mm[:] = b"\x00" * REGION_SIZE
    struct.pack_into(
        HEADER_FMT,
        mm,
        0,
        LINK_SHM_MAGIC,
        LINK_SHM_VERSION,
        LINK_SHM_CAP,
        SLOT_SIZE,
        0,
        0,
        0,
        0,
        0,
    )


def load_u64(mm: mmap.mmap, off: int) -> int:
    return struct.unpack_from(f"{NATIVE}Q", mm, off)[0]


def store_u64(mm: mmap.mmap, off: int, value: int) -> None:
    struct.pack_into(f"{NATIVE}Q", mm, off, value)


def push_update(mm: mmap.mmap, dev: str, src_ip: str, loss: int, delay_us: int, jitter_us: int, rate_mbit: int) -> bool:
    write_pos = load_u64(mm, WRITE_POS_OFF)
    read_pos = load_u64(mm, READ_POS_OFF)

    if write_pos - read_pos >= LINK_SHM_CAP:
        prod_drops = load_u64(mm, PROD_DROPS_OFF) + 1
        store_u64(mm, PROD_DROPS_OFF, prod_drops)
        return False

    dev_bytes = dev.encode("ascii")
    if len(dev_bytes) >= IF_NAMESIZE:
        raise ValueError(f"dev name too long: {dev}")
    dev_wire = dev_bytes + b"\x00" * (IF_NAMESIZE - len(dev_bytes))

    slot_off = HEADER_SIZE + (write_pos % LINK_SHM_CAP) * SLOT_SIZE
    struct.pack_into(
        SLOT_FMT,
        mm,
        slot_off,
        dev_wire,
        ip_to_src_ip_be(src_ip),
        loss,
        delay_us,
        jitter_us,
        rate_mbit,
        0,
        time.monotonic_ns(),
    )
    store_u64(mm, WRITE_POS_OFF, write_pos + 1)
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description="Burst updates through shared memory ring.")
    ap.add_argument("--shm", default=DEFAULT_SHM_NAME, help="shared memory name or absolute path")
    ap.add_argument("--sid", type=int, default=1, help="match dev veth<hex>.0.<sid> (default 1)")
    ap.add_argument("--nodes", type=int, default=100, help="use first N discovered nodes")
    ap.add_argument("--ip-prefix", default="10.0.0.")
    ap.add_argument("--ip-mode", choices=["match", "base"], default="match")
    ap.add_argument("--ip-base", type=int, default=2)
    ap.add_argument("--loss", type=int, default=0)
    ap.add_argument("--delay-us", type=int, default=30000)
    ap.add_argument("--jitter-us", type=int, default=5000)
    ap.add_argument("--rate-mbit", type=int, default=100)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--warmup", type=int, default=0)
    ap.add_argument("--check-devs", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    devs = list_devs(args.sid)
    if not devs:
        raise SystemExit(f"no devs matched veth<hex>.0.{args.sid} under /sys/class/net")

    devs = devs[: args.nodes]
    node_ids = [nid for _, nid in devs]

    def ip_of(node_id: int) -> str:
        if args.ip_mode == "match":
            return f"{args.ip_prefix}{node_id}"
        return f"{args.ip_prefix}{(node_id + args.ip_base - 1)}"

    if args.check_devs:
        show = devs[:5] + ([("...", -1)] if len(devs) > 10 else []) + devs[-5:]
        for dev, nid in show:
            if dev == "...":
                print("...")
            else:
                print(f"node_id={nid:3d}: dev={dev} ip={ip_of(nid)}")
        print(f"[discover] matched={len(list_devs(args.sid))} using={len(devs)} ip_mode={args.ip_mode}")

    updates: List[Tuple[str, str, int, int, int, int]] = []
    for recv_dev, recv_id in devs:
        for src_id in node_ids:
            if src_id == recv_id:
                continue
            updates.append(
                (
                    recv_dev,
                    ip_of(src_id),
                    args.loss,
                    args.delay_us,
                    args.jitter_us,
                    args.rate_mbit,
                )
            )

    print(f"[gen] sid={args.sid} nodes={len(devs)} updates={len(updates)}")

    if args.dry_run:
        return

    shm_path = resolve_shm_path(args.shm)
    fd = os.open(shm_path, os.O_CREAT | os.O_RDWR, 0o666)
    try:
        os.ftruncate(fd, REGION_SIZE)
        mm = mmap.mmap(fd, REGION_SIZE, access=mmap.ACCESS_WRITE)
    finally:
        os.close(fd)

    try:
        init_region(mm)

        def send_round(tag: str) -> float:
            start = time.perf_counter()
            ok = 0
            dropped = 0
            for dev, src_ip, loss, delay_us, jitter_us, rate_mbit in updates:
                if push_update(mm, dev, src_ip, loss, delay_us, jitter_us, rate_mbit):
                    ok += 1
                else:
                    dropped += 1
            dt = time.perf_counter() - start
            rate = ok / dt if dt > 0 else 0.0
            print(f"[{tag}] shm={shm_path} ok={ok} dropped={dropped} dt={dt:.6f}s updates/s={rate:.1f}")
            return dt

        for i in range(args.warmup):
            send_round(f"warmup{i+1}")

        dts = [send_round(f"run{i+1}") for i in range(args.repeat)]
        if dts:
            best = min(dts)
            avg = sum(dts) / len(dts)
            print(f"[summary] repeat={args.repeat} best_dt={best:.6f}s avg_dt={avg:.6f}s "
                  f"best_updates/s={len(updates)/best:.1f} avg_updates/s={len(updates)/avg:.1f}")
    finally:
        mm.close()


if __name__ == "__main__":
    main()
