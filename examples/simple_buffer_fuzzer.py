#!/usr/bin/env python3
"""Simple Buffer Fuzzer Example

This example demonstrates using BitFactory to fuzz a binary executable with
buffer mutations. It creates a simple container with a buffer, applies various
buffer mutators, and tests each mutation against a target binary.

Usage:
    python simple_buffer_fuzzer.py <path_to_binary> [initial_data]

Example:
    python simple_buffer_fuzzer.py /usr/bin/file_parser "test data"
    python simple_buffer_fuzzer.py ./vulnerable_app
"""

import argparse
import subprocess
import sys

from bitfactory import (
    BFBuffer,
    BFContainer,
    BFMutatable,
    create_buffer_mutator_suite,
)


class CrashInfo:
    """Information about a crash"""

    def __init__(self, mutation_result, return_code: int, stdout: bytes, stderr: bytes):
        self.mutation_result = mutation_result
        self.return_code = return_code
        self.stdout = stdout
        self.stderr = stderr


def run_binary_with_input(
    binary_path: str, input_data: bytes, timeout: int = 5
) -> tuple[int, bytes, bytes]:
    """Run a binary with the given input data.

    Args:
        binary_path: Path to the binary executable (can include arguments)
        input_data: Data to send to the binary's stdin
        timeout: Maximum execution time in seconds

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    try:
        # Split the binary_path in case it includes arguments
        import shlex
        cmd = shlex.split(binary_path)

        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, b"", b"TIMEOUT: Process exceeded timeout"
    except Exception as e:
        return -2, b"", f"ERROR: {e}".encode()


def is_crash(return_code: int, baseline_code: int = 0) -> bool:
    """Determine if a return code indicates a crash or error.

    Args:
        return_code: The process return code
        baseline_code: The baseline return code (typically 0)

    Returns:
        True if the return code indicates a crash or unexpected behavior
    """
    # Negative return codes often indicate signals (crashes)
    if return_code < 0:
        return True
    # In Unix, signal crashes show up as 128 + signal_number
    if return_code > 128:
        return True
    # Any non-zero code different from baseline is suspicious
    return bool(return_code != baseline_code and return_code != 0)


def print_crash_info(crash: CrashInfo) -> None:
    """Print detailed information about a crash.

    Args:
        crash: CrashInfo object containing crash details
    """
    result = crash.mutation_result

    print("\n" + "=" * 80)
    print("CRASH DETECTED!")
    print("=" * 80)
    print(f"Mutation Index: {result.index}")
    print(f"Field Path: {result.path}")
    print(f"Mutator: {result.mutator_name}")
    print(f"Description: {result.description}")
    print(f"Return Code: {crash.return_code}")

    # Print metadata if available
    if result.metadata:
        print("\nMetadata:")
        if "references" in result.metadata:
            print("  References:")
            for ref in result.metadata["references"]:
                source = ref.get("source", "")
                ref_id = ref.get("id", "")
                name = ref.get("name", "")
                if name:
                    print(f"    {source}-{ref_id}: {name}")
                else:
                    print(f"    {source}-{ref_id}")
        if "tags" in result.metadata:
            print(f"  Tags: {', '.join(result.metadata['tags'])}")
        if "category" in result.metadata:
            print(f"  Category: {result.metadata['category']}")

    print(f"\nOriginal Value: {result.original_value!r}")
    print(f"Mutated Value: {result.mutated_value!r}")
    print(f"Packed Data Length: {len(result.packed_data)} bytes")

    # Show hex dump of first 64 bytes
    print("\nPacked Data (first 64 bytes):")
    hex_data = result.packed_data[:64].hex()
    for i in range(0, len(hex_data), 32):
        print(f"  {hex_data[i:i+32]}")

    if crash.stderr:
        print("\nStderr Output:")
        stderr_text = crash.stderr.decode("utf-8", errors="replace")
        for line in stderr_text.split("\n")[:20]:  # Limit to first 20 lines
            print(f"  {line}")

    print("=" * 80)


def main():
    """Main fuzzing function"""
    parser = argparse.ArgumentParser(
        description="Simple buffer fuzzer using BitFactory mutations"
    )
    parser.add_argument("binary", help="Path to the binary executable to fuzz")
    parser.add_argument(
        "initial_data",
        nargs="?",
        default="AAAA",
        help="Initial data for the buffer (default: AAAA)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout for each execution in seconds (default: 5)",
    )

    args = parser.parse_args()

    # Create a simple container with a buffer
    container = BFContainer()
    container.data = BFBuffer(args.initial_data.encode())

    # Create mutatable wrapper and add buffer mutators
    mutatable = BFMutatable(container)
    for mutator in create_buffer_mutator_suite():
        mutatable.add_mutator(mutator)

    # Get total mutation count
    total_mutations = mutatable.total_count()

    print("BitFactory Simple Buffer Fuzzer")
    print("=" * 80)
    print(f"Target Binary: {args.binary}")
    print(f"Initial Data: {args.initial_data!r}")
    print(f"Total Mutations: {total_mutations}")
    print(f"Timeout: {args.timeout}s")
    print("=" * 80)
    print()

    # Test the binary with baseline input first
    print("Testing baseline input...")
    baseline_rc, baseline_stdout, baseline_stderr = run_binary_with_input(
        args.binary, container.pack(), args.timeout
    )
    print(f"Baseline return code: {baseline_rc}")
    if baseline_rc != 0:
        print(
            f"WARNING: Baseline execution returned non-zero code: {baseline_rc}"
        )
    print()

    # Iterate through all mutations
    print("Starting mutation fuzzing...")
    crashes = []
    tested = 0

    for result in mutatable:
        tested += 1

        # Progress indicator every 10 mutations
        if tested % 10 == 0:
            print(f"Progress: {tested}/{total_mutations} mutations tested...", end="\r")

        # Run the binary with mutated input
        return_code, stdout, stderr = run_binary_with_input(
            args.binary, result.packed_data, args.timeout
        )

        # Check if it crashed (comparing to baseline)
        if is_crash(return_code, baseline_rc):
            crash = CrashInfo(result, return_code, stdout, stderr)
            crashes.append(crash)
            print_crash_info(crash)

            # Exit on first crash as requested
            print(f"\nStopping after first crash (tested {tested} of {total_mutations} mutations)")
            sys.exit(1)

    # If we get here, no crashes were found
    print(f"\nCompleted: {tested}/{total_mutations} mutations tested")
    print("No crashes detected!")
    sys.exit(0)


if __name__ == "__main__":
    main()
