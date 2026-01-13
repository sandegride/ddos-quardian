#!/usr/bin/env python3
"""Generate a synthetic CSV dataset for the demo DDoS classifier.

Schema:
  total_packets,total_bytes,unique_src_ips,max_per_src,avg_pkt_size,
  tcp_ratio,udp_ratio,icmp_ratio,syn_ratio,src_entropy,label

WARNING: This dataset is synthetic and intended only for demonstrations.
"""

from __future__ import annotations

import argparse
import csv
import math
import random

FEATURES = [
    "total_packets",
    "total_bytes",
    "unique_src_ips",
    "max_per_src",
    "avg_pkt_size",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "syn_ratio",
    "src_entropy",
]


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def gen_normal(rng: random.Random) -> list[float]:
    total_packets = int(clamp(rng.lognormvariate(math.log(200), 0.6), 30, 1200))
    avg_pkt_size = clamp(rng.gauss(600, 150), 150, 1400)
    total_bytes = int(total_packets * avg_pkt_size * rng.uniform(0.8, 1.2))

    unique_src_ips = int(clamp(rng.gauss(10, 5), 1, 40))
    base = total_packets / max(1, unique_src_ips)
    max_per_src = int(clamp(base * rng.uniform(1.2, 3.5), 5, total_packets))

    tcp_ratio = clamp(rng.uniform(0.75, 0.98), 0.0, 1.0)
    udp_ratio = clamp(rng.uniform(0.01, 0.20), 0.0, 1.0 - tcp_ratio)
    remaining = 1.0 - tcp_ratio - udp_ratio
    icmp_ratio = clamp(rng.uniform(0.0, min(0.05, remaining)), 0.0, 1.0)

    syn_ratio = clamp(rng.uniform(0.01, 0.12), 0.0, 1.0)
    src_entropy = clamp(rng.uniform(0.15, 0.65), 0.0, 1.0)

    return [
        total_packets,
        total_bytes,
        unique_src_ips,
        max_per_src,
        avg_pkt_size,
        tcp_ratio,
        udp_ratio,
        icmp_ratio,
        syn_ratio,
        src_entropy,
        0,
    ]


def gen_attack(rng: random.Random) -> list[float]:
    kind = rng.choice(["udp_flood", "syn_flood", "http_flood"])

    if kind == "udp_flood":
        total_packets = int(clamp(rng.lognormvariate(math.log(9000), 0.6), 2000, 40000))
        avg_pkt_size = clamp(rng.gauss(420, 120), 100, 900)
        udp_ratio = clamp(rng.uniform(0.65, 0.98), 0.0, 1.0)
        tcp_ratio = clamp(rng.uniform(0.02, 0.30), 0.0, 1.0 - udp_ratio)
        remaining = 1.0 - udp_ratio - tcp_ratio
        icmp_ratio = clamp(rng.uniform(0.0, min(0.05, remaining)), 0.0, 1.0)
        syn_ratio = clamp(rng.uniform(0.0, 0.08), 0.0, 1.0)

    elif kind == "syn_flood":
        total_packets = int(clamp(rng.lognormvariate(math.log(12000), 0.55), 3000, 50000))
        avg_pkt_size = clamp(rng.gauss(90, 25), 60, 200)
        tcp_ratio = clamp(rng.uniform(0.85, 0.99), 0.0, 1.0)
        udp_ratio = clamp(rng.uniform(0.0, 0.10), 0.0, 1.0 - tcp_ratio)
        remaining = 1.0 - tcp_ratio - udp_ratio
        icmp_ratio = clamp(rng.uniform(0.0, min(0.03, remaining)), 0.0, 1.0)
        syn_ratio = clamp(rng.uniform(0.55, 0.98), 0.0, 1.0)

    else:  # http_flood
        total_packets = int(clamp(rng.lognormvariate(math.log(8000), 0.6), 2000, 40000))
        avg_pkt_size = clamp(rng.gauss(950, 250), 250, 2000)
        tcp_ratio = clamp(rng.uniform(0.90, 0.99), 0.0, 1.0)
        udp_ratio = clamp(rng.uniform(0.0, 0.06), 0.0, 1.0 - tcp_ratio)
        remaining = 1.0 - tcp_ratio - udp_ratio
        icmp_ratio = clamp(rng.uniform(0.0, min(0.02, remaining)), 0.0, 1.0)
        syn_ratio = clamp(rng.uniform(0.02, 0.20), 0.0, 1.0)

    total_bytes = int(total_packets * avg_pkt_size * rng.uniform(0.9, 1.3))

    # distributed attacks dominate the demo set
    if rng.random() < 0.75:
        unique_src_ips = int(clamp(rng.lognormvariate(math.log(300), 0.8), 50, 3000))
        base = total_packets / max(1, unique_src_ips)
        max_per_src = int(clamp(base * rng.uniform(1.5, 4.0), 20, total_packets))
        src_entropy = clamp(rng.uniform(0.70, 0.98), 0.0, 1.0)
    else:
        unique_src_ips = int(clamp(rng.gauss(5, 3), 1, 30))
        max_per_src = int(clamp(total_packets * rng.uniform(0.3, 0.9), 500, total_packets))
        src_entropy = clamp(rng.uniform(0.20, 0.60), 0.0, 1.0)

    return [
        total_packets,
        total_bytes,
        unique_src_ips,
        max_per_src,
        avg_pkt_size,
        tcp_ratio,
        udp_ratio,
        icmp_ratio,
        syn_ratio,
        src_entropy,
        1,
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="./data/train_sample.csv", help="Output CSV path")
    ap.add_argument("--n_normal", type=int, default=300)
    ap.add_argument("--n_attack", type=int, default=300)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    rows = [gen_normal(rng) for _ in range(args.n_normal)] + [gen_attack(rng) for _ in range(args.n_attack)]
    rng.shuffle(rows)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(FEATURES + ["label"])
        for r in rows:
            # keep floats readable
            out = []
            for v in r[:-1]:
                out.append(f"{float(v):.6f}" if isinstance(v, float) else str(v))
            out.append(str(int(r[-1])))
            w.writerow(out)

    print(f"Saved {len(rows)} rows to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
