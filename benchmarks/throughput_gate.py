"""Horizontal runtime throughput gate for 1K/10K requests per second."""
import argparse
from concurrent.futures import ProcessPoolExecutor
import os
import time

from load_matrix import _raw, _reg
from policy_enforcement import RuntimeGatewayPipeline


def run_partition(count):
    pipeline, raw = RuntimeGatewayPipeline(_reg()), _raw()
    for _ in range(500):
        pipeline.process(raw,"mcp")
    started = time.perf_counter()
    for _ in range(count):
        pipeline.process(raw,"mcp")
    return count, time.perf_counter()-started


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--requests',type=int,default=100000)
    parser.add_argument('--workers',type=int,default=min(8,os.cpu_count() or 2))
    parser.add_argument('--target-rps',type=int,default=10000)
    args = parser.parse_args()
    if not 1 <= args.workers <= 64 or args.requests < args.workers:
        raise SystemExit('invalid bounded load configuration')
    counts = [args.requests//args.workers]*args.workers
    for index in range(args.requests % args.workers): counts[index] += 1
    started = time.perf_counter()
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(run_partition,counts))
    elapsed = time.perf_counter()-started
    rps = int(args.requests/elapsed)
    print(f'Horizontal hot-path throughput: {rps} req/s; requests={args.requests}; workers={args.workers}; wall={elapsed:.3f}s')
    print('10K GATE PASSED' if rps >= args.target_rps else '10K GATE FAILED')
    return 0 if rps >= args.target_rps else 1


if __name__ == '__main__':
    raise SystemExit(main())
