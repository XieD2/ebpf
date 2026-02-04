#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
import socket
import time
from typing import List, Tuple

DEV_RE_TMPL = r"^veth([0-9a-f]+)\.0\.{sid}$"


def list_devs(sid: int) -> List[Tuple[str, int]]:
    """
    返回 [(dev_name, node_id_decimal)]，node_id_decimal 由 veth 后缀 hex 解析得到。
    例如 veth1a.0.1 -> node_id=26
    """
    pat = re.compile(DEV_RE_TMPL.format(sid=sid))
    out: List[Tuple[str, int]] = []
    for name in os.listdir("/sys/class/net"):
        m = pat.match(name)
        if not m:
            continue
        node_hex = m.group(1)
        try:
            node_id = int(node_hex, 16)
        except ValueError:
            continue
        if 1 <= node_id <= 254:
            out.append((name, node_id))
    out.sort(key=lambda x: x[1])
    return out


def make_group(dev: str, src_ip: str, loss: int, delay_us: int, jitter_us: int, rate_mbit: int) -> str:
    return f"{dev} {src_ip} {loss} {delay_us} {jitter_us} {rate_mbit}"


def batch_payload(groups: List[str], max_datagram_bytes: int) -> List[bytes]:
    payloads: List[bytes] = []
    cur: List[str] = []
    cur_len = 0
    for g in groups:
        add_len = len(g) + (1 if cur else 0)  # + '\n'
        if cur and (cur_len + add_len) > max_datagram_bytes:
            payloads.append(("\n".join(cur)).encode("ascii"))
            cur = [g]
            cur_len = len(g)
        else:
            cur_len = cur_len + add_len if cur else len(g)
            cur.append(g)
    if cur:
        payloads.append(("\n".join(cur)).encode("ascii"))
    return payloads


def main():
    ap = argparse.ArgumentParser(description="Burst updates (auto-discover veth hex devs).")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)

    ap.add_argument("--sid", type=int, default=1, help="match dev veth<hex>.0.<sid> (default 1)")
    ap.add_argument("--nodes", type=int, default=100,
                    help="use first N discovered nodes (sorted by node_id). default 100")

    ap.add_argument("--ip-prefix", default="10.0.0.")
    ap.add_argument("--ip-mode", choices=["match", "base"], default="match",
                    help="match: ip last octet == node_id (recommended). "
                         "base: node_id=1 maps to 10.0.0.<ip-base> (legacy)")
    ap.add_argument("--ip-base", type=int, default=2,
                    help="only for --ip-mode base: node_id=1 maps to 10.0.0.<ip-base>")

    ap.add_argument("--loss", type=int, default=0)
    ap.add_argument("--delay-us", type=int, default=30000)
    ap.add_argument("--jitter-us", type=int, default=5000)
    ap.add_argument("--rate-mbit", type=int, default=100)

    ap.add_argument("--max-dgram", type=int, default=1200)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--warmup", type=int, default=0)
    ap.add_argument("--sleep-ms", type=float, default=0.0)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--check-devs", action="store_true")

    args = ap.parse_args()

    devs = list_devs(args.sid)
    if not devs:
        raise SystemExit(f"no devs matched veth<hex>.0.{args.sid} under /sys/class/net")

    devs = devs[: args.nodes]
    node_ids = [nid for _, nid in devs]

    def ip_of(node_id: int) -> str:
        if args.ip_mode == "match":
            # 强一致：vethX.0.sid -> 10.0.0.X
            return f"{args.ip_prefix}{node_id}"
        # legacy：node_id=1 -> 10.0.0.<ip-base>
        return f"{args.ip_prefix}{(node_id + args.ip_base - 1)}"

    if args.check_devs:
        show = devs[:5] + ([("...", -1)] if len(devs) > 10 else []) + devs[-5:]
        for dev, nid in show:
            if dev == "...":
                print("...")
            else:
                print(f"node_id={nid:3d}: dev={dev} ip={ip_of(nid)}")
        print(f"[discover] matched={len(list_devs(args.sid))} using={len(devs)} ip_mode={args.ip_mode}")

        if args.ip_mode == "match":
            # 额外提示：这模式要求节点 IP 必须等于 node_id
            print("[note] ip_mode=match assumes your node IPs are exactly 10.0.0.<node_id>")

    # 生成更新：对每个 recv_dev，给所有 src_id(按 node_id) 生成一条（排除自己）
    groups: List[str] = []
    for recv_dev, recv_id in devs:
        for src_id in node_ids:
            if src_id == recv_id:
                continue
            groups.append(
                make_group(
                    recv_dev,
                    ip_of(src_id),
                    args.loss,
                    args.delay_us,
                    args.jitter_us,
                    args.rate_mbit,
                )
            )

    total_updates = len(groups)  # N*(N-1)
    payloads = batch_payload(groups, args.max_dgram)

    print(f"[gen] sid={args.sid} nodes={len(devs)} updates={total_updates} datagrams={len(payloads)} max_dgram={args.max_dgram}")
    if payloads:
        sizes = [len(p) for p in payloads]
        print(f"[gen] payload bytes: min={min(sizes)} avg={sum(sizes)/len(sizes):.1f} max={max(sizes)}")

    if args.dry_run:
        return

    addr = (args.host, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 可选：增大发送缓冲，减少 burst 阻塞
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except OSError:
        pass

    def send_round(tag: str) -> float:
        start = time.perf_counter()
        sent_bytes = 0
        for p in payloads:
            sock.sendto(p, addr)
            sent_bytes += len(p)
            if args.sleep_ms > 0:
                time.sleep(args.sleep_ms / 1000.0)
        dt = time.perf_counter() - start
        print(f"[{tag}] pkts={len(payloads)} bytes={sent_bytes} dt={dt:.6f}s "
              f"updates/s={total_updates/dt:.1f} pkts/s={len(payloads)/dt:.1f} MiB/s={(sent_bytes/dt)/(1024*1024):.2f}")
        return dt

    for i in range(args.warmup):
        send_round(f"warmup{i+1}")

    dts = [send_round(f"run{i+1}") for i in range(args.repeat)]
    if dts:
        best = min(dts)
        avg = sum(dts) / len(dts)
        print(f"[summary] repeat={args.repeat} best_dt={best:.6f}s avg_dt={avg:.6f}s "
              f"best_updates/s={total_updates/best:.1f} avg_updates/s={total_updates/avg:.1f}")

    sock.close()


if __name__ == "__main__":
    main()
