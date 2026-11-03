import argparse
import contextlib
import io
import platform
import statistics
import sys
import time

from datetime import datetime
from pathlib import Path

# Add project root to Python import path.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from resolver import resolve_test


def benchmark_domain(domain, runs):

    timings = []
    successful_runs = 0
    failed_runs = 0
    errors = []

    print(f"\nBenchmarking: {domain}")

    for run in range(1, runs + 1):

        print(f"Run {run}/{runs}...", end=" ", flush=True)

        start_time = time.perf_counter()

        try:
            # Suppress resolver's normal output during benchmarking.
            with contextlib.redirect_stdout(io.StringIO()):
                result = resolve_test(domain)

            elapsed = time.perf_counter() - start_time
            timings.append(elapsed)

            if result:
                successful_runs += 1
                print(f"Success ({elapsed:.4f} seconds)")
            else:
                failed_runs += 1
                print(f"Failed ({elapsed:.4f} seconds)")

        except Exception as error:
            elapsed = time.perf_counter() - start_time
            failed_runs += 1
            errors.append(f"Run {run}: {type(error).__name__}: {error}")

            print(f"Error ({elapsed:.4f} seconds)")

    successful_timings = [
        timing
        for timing in timings
        if timing > 0
    ]

    if successful_timings:
        average_time = statistics.mean(successful_timings)
        median_time = statistics.median(successful_timings)
        minimum_time = min(successful_timings)
        maximum_time = max(successful_timings)
    else:
        average_time = median_time = None
        minimum_time = maximum_time = None

    return {
        "domain": domain,
        "runs": runs,
        "successful_runs": successful_runs,
        "failed_runs": failed_runs,
        "timings": timings,
        "average": average_time,
        "median": median_time,
        "minimum": minimum_time,
        "maximum": maximum_time,
        "errors": errors
    }


def generate_report(results):

    report = []

    report.append("=" * 60)
    report.append("ITERATIVE DNS RESOLVER - BENCHMARK REPORT")
    report.append("=" * 60)

    report.append(
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    report.append(f"Python Version: {platform.python_version()}")
    report.append(f"Platform: {platform.platform()}")

    report.append("\nBENCHMARK RESULTS")
    report.append("-" * 60)

    for result in results:

        report.append(f"\nDomain: {result['domain']}")
        report.append(f"Total Runs: {result['runs']}")
        report.append(
            f"Successful Runs: {result['successful_runs']}"
        )
        report.append(f"Failed Runs: {result['failed_runs']}")

        report.append("\nIndividual Execution Times:")

        for index, timing in enumerate(result["timings"], start=1):
            report.append(
                f"  Run {index}: {timing:.4f} seconds"
            )

        if result["average"] is not None:

            report.append("\nPerformance Statistics:")
            report.append(
                f"  Average: {result['average']:.4f} seconds"
            )
            report.append(
                f"  Median: {result['median']:.4f} seconds"
            )
            report.append(
                f"  Minimum: {result['minimum']:.4f} seconds"
            )
            report.append(
                f"  Maximum: {result['maximum']:.4f} seconds"
            )

        if result["errors"]:
            report.append("\nErrors:")

            for error in result["errors"]:
                report.append(f"  {error}")

        report.append("-" * 60)

    return "\n".join(report)


def main():

    parser = argparse.ArgumentParser(
        description="Benchmark the iterative DNS resolver"
    )

    parser.add_argument(
        "domains",
        nargs="+",
        help="Domains to benchmark"
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of benchmark runs per domain (default: 3)"
    )

    args = parser.parse_args()

    if args.runs < 1:
        parser.error("--runs must be at least 1")

    results = []

    for domain in args.domains:
        result = benchmark_domain(domain, args.runs)
        results.append(result)

    # Create results directory if it doesn't exist.
    results_dir = Path(__file__).resolve().parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    # Generate a unique timestamped filename.
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    output_file = results_dir / f"benchmark_{timestamp}.txt"

    report = generate_report(results)

    output_file.write_text(report, encoding="utf-8")

    print("\nBenchmark completed!")
    print(f"Results saved to: {output_file}")


if __name__ == "__main__":
    main()
