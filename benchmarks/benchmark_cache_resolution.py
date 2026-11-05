import csv
import statistics
import sys
import time
import argparse

from datetime import datetime
from pathlib import Path

# Add project root to Python import path.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from resolver import dns_cache, resolve_test


ITERATIONS = 20


def measure_resolution(domain):
    start_time = time.perf_counter()

    try:
        result = resolve_test(domain)
        elapsed = time.perf_counter() - start_time

        return {
            "success": bool(result),
            "latency_ms": elapsed * 1000
        }

    except Exception as error:
        elapsed = time.perf_counter() - start_time

        print(f"Error resolving {domain}: {error}")

        return {
            "success": False,
            "latency_ms": elapsed * 1000
        }


def benchmark_domain(domain):
    cold_timings = []
    warm_timings = []

    cold_successes = 0
    warm_successes = 0

    print(f"\nBenchmarking: {domain}")

    for iteration in range(1, ITERATIONS + 1):

        # Cold-cache resolution.
        dns_cache.clear()

        cold_result = measure_resolution(domain)

        cold_timings.append(cold_result["latency_ms"])

        if cold_result["success"]:
            cold_successes += 1

            # Warm-cache resolution.
            warm_result = measure_resolution(domain)

            warm_timings.append(warm_result["latency_ms"])

            if warm_result["success"]:
                warm_successes += 1

        else:
            warm_timings.append(None)

        print(
            f"Run {iteration}/{ITERATIONS} | "
            f"Cold: {cold_result['latency_ms']:.4f} ms | "
            f"Warm: "
            f"{warm_timings[-1]:.4f} ms"
            if warm_timings[-1] is not None
            else f"Run {iteration}/{ITERATIONS} | "
                 f"Cold: {cold_result['latency_ms']:.4f} ms | "
                 "Warm: Skipped"
        )

    successful_cold = [
        value for value in cold_timings
        if value is not None
    ]

    successful_warm = [
        value for value in warm_timings
        if value is not None
    ]

    cold_average = (
        statistics.mean(successful_cold)
        if successful_cold else None
    )

    warm_average = (
        statistics.mean(successful_warm)
        if successful_warm else None
    )

    cold_median = (
        statistics.median(successful_cold)
        if successful_cold else None
    )

    warm_median = (
        statistics.median(successful_warm)
        if successful_warm else None
    )

    time_saved_percentage = None

    if cold_average and warm_average is not None:
        time_saved_percentage = (
            (cold_average - warm_average) / cold_average
        ) * 100

    return {
        "domain": domain,
        "iterations": ITERATIONS,
        "cold_successes": cold_successes,
        "warm_successes": warm_successes,
        "cold_average": cold_average,
        "warm_average": warm_average,
        "cold_median": cold_median,
        "warm_median": warm_median,
        "time_saved_percentage": time_saved_percentage,
        "cold_timings": cold_timings,
        "warm_timings": warm_timings
    }


def export_results(results):
    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_file = (
        results_dir /
        f"cache_resolution_{timestamp}.csv"
    )

    with output_file.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.writer(csv_file)

        writer.writerow([
            "Domain",
            "Iteration",
            "Cold Latency (ms)",
            "Cold Success",
            "Warm Latency (ms)",
            "Warm Success"
        ])

        for result in results:

            for index in range(result["iterations"]):

                writer.writerow([
                    result["domain"],
                    index + 1,
                    result["cold_timings"][index],
                    result["cold_timings"][index] is not None,
                    result["warm_timings"][index],
                    result["warm_timings"][index] is not None
                ])

    print(f"\nResults exported to: {output_file}")


def print_summary(results):
    print("\n" + "=" * 60)
    print("PYRESOLVER - CACHE RESOLUTION BENCHMARK")
    print("=" * 60)

    for result in results:

        print(f"\nDomain: {result['domain']}")

        print(
            f"Cold successes: "
            f"{result['cold_successes']}/{result['iterations']}"
        )

        print(
            f"Warm successes: "
            f"{result['warm_successes']}/{result['iterations']}"
        )

        if result["cold_average"] is not None:
            print(
                f"Cold average: "
                f"{result['cold_average']:.4f} ms"
            )
            print(
                f"Cold median: "
                f"{result['cold_median']:.4f} ms"
            )

        if result["warm_average"] is not None:
            print(
                f"Warm average: "
                f"{result['warm_average']:.4f} ms"
            )
            print(
                f"Warm median: "
                f"{result['warm_median']:.4f} ms"
            )

        if result["time_saved_percentage"] is not None:
            print(
                f"Time saved: "
                f"{result['time_saved_percentage']:.2f}%"
            )

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark cold-cache and warm-cache DNS resolution"
    )

    parser.add_argument(
        "domains",
        nargs="+",
        help="Domains to benchmark"
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=20,
        help="Number of benchmark iterations per domain (default: 20)"
    )

    args = parser.parse_args()

    if args.runs < 1:
        parser.error("--runs must be at least 1")

    global ITERATIONS
    ITERATIONS = args.runs

    results = []

    for domain in args.domains:
        results.append(benchmark_domain(domain))

    print_summary(results)
    export_results(results)


if __name__ == "__main__":
    main()
