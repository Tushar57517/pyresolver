import csv
import statistics
import sys
import time

from datetime import datetime
from pathlib import Path

# Add project root to Python import path.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from resolver import dns_cache, store_in_cache, get_from_cache


ITERATIONS = 10_000
WARMUP_RUNS = 100

TEST_DOMAIN = "benchmark.example.com"
TEST_IP = "192.0.2.1"


def benchmark_cache_lookup(test_type, domain, iterations):
    timings = []
    cache_hits = 0

    print(f"\nBenchmarking cache {test_type}...")

    # Warm-up phase.
    for _ in range(WARMUP_RUNS):
        get_from_cache(domain)

    # Measurement phase.
    for iteration in range(1, iterations + 1):
        start_time = time.perf_counter()

        result = get_from_cache(domain)

        elapsed = time.perf_counter() - start_time

        latency_ms = elapsed * 1000
        cache_hit = result is not None

        timings.append(latency_ms)

        if cache_hit:
            cache_hits += 1

        if iteration % 1000 == 0:
            print(f"Completed {iteration}/{iterations} lookups")

    return {
        "test_type": test_type,
        "timings": timings,
        "cache_hits": cache_hits,
        "cache_misses": iterations - cache_hits,
        "average": statistics.mean(timings),
        "median": statistics.median(timings),
        "minimum": min(timings),
        "maximum": max(timings)
    }


def prepare_cache_hit():
    dns_cache.clear()

    store_in_cache(
        TEST_DOMAIN,
        [{
            "value": TEST_IP,
            "ttl": 3600
        }]
    )


def prepare_cache_miss():
    dns_cache.clear()


def test_expired_cache():
    dns_cache.clear()

    store_in_cache(
        TEST_DOMAIN,
        [{
            "value": TEST_IP,
            "ttl": 3600
        }]
    )

    # Force the cached record to expire.
    dns_cache[TEST_DOMAIN][0]["expires_at"] = time.time() - 1

    result = get_from_cache(TEST_DOMAIN)

    expired_correctly = result is None
    entry_removed = TEST_DOMAIN not in dns_cache

    print("\nExpired cache validation:")
    print(f"Expired record rejected: {expired_correctly}")
    print(f"Expired entry removed: {entry_removed}")

    return expired_correctly and entry_removed


def save_results_to_csv(results):
    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_file = results_dir / f"cache_benchmark_{timestamp}.csv"

    with output_file.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)

        writer.writerow([
            "Domain",
            "Test Type",
            "Iteration",
            "Latency (ms)",
            "Cache Hit"
        ])

        for result in results:
            for index, timing in enumerate(result["timings"], start=1):
                writer.writerow([
                    TEST_DOMAIN,
                    result["test_type"],
                    index,
                    f"{timing:.6f}",
                    index <= result["cache_hits"]
                    if result["test_type"] == "Cache Hit"
                    else False
                ])

    print(f"\nCSV results saved to: {output_file}")


def print_summary(results):
    print("\n" + "=" * 55)
    print("PYRESOLVER - CACHE BENCHMARK SUMMARY")
    print("=" * 55)

    for result in results:
        print(f"\nTest: {result['test_type']}")
        print(f"Iterations: {len(result['timings'])}")
        print(f"Cache hits: {result['cache_hits']}")
        print(f"Cache misses: {result['cache_misses']}")
        print(f"Average latency: {result['average']:.6f} ms")
        print(f"Median latency: {result['median']:.6f} ms")
        print(f"Minimum latency: {result['minimum']:.6f} ms")
        print(f"Maximum latency: {result['maximum']:.6f} ms")

    print("\n" + "=" * 55)


def main():
    results = []

    # Scenario 1: Cache hit.
    prepare_cache_hit()

    hit_result = benchmark_cache_lookup(
        "Cache Hit",
        TEST_DOMAIN,
        ITERATIONS
    )

    results.append(hit_result)

    # Scenario 2: Cache miss.
    prepare_cache_miss()

    miss_result = benchmark_cache_lookup(
        "Cache Miss",
        TEST_DOMAIN,
        ITERATIONS
    )

    results.append(miss_result)

    # Scenario 3: Expiration correctness.
    expiration_passed = test_expired_cache()

    print_summary(results)

    save_results_to_csv(results)

    print(f"\nExpiration test passed: {expiration_passed}")


if __name__ == "__main__":
    main()
