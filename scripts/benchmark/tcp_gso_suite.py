#!/usr/bin/env python3
"""Canonical manifest-driven TCP comparator with paired GSO-on/off rows."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import glob
import hashlib
import json
import math
import os
import pathlib
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Iterable


SCHEMA_VERSION = 1
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
UDP_SEGMENT_CMSG_PATTERN = re.compile(
    r"\bcmsg_level=(?:SOL_UDP|IPPROTO_UDP),\s*"
    r"cmsg_type=(?:UDP_SEGMENT|0x0*67|103)\b",
    re.IGNORECASE,
)
UDP_SEGMENT_SETSOCKOPT_PATTERN = re.compile(
    r"\bsetsockopt\([^,]+,\s*(?:SOL_UDP|IPPROTO_UDP|0x0*11|17),\s*"
    r"(?:UDP_SEGMENT|0x0*67|103)\b",
    re.IGNORECASE,
)
SUCCESSFUL_SYSCALL_PATTERN = re.compile(r"\)\s+=\s+[1-9][0-9]*(?:\s.*)?$")
MODES = ("on", "off")
CONTROLLED_ENV = {
    "BENCH_CLIENT_PRELOAD",
    "BENCH_SERVER_PRELOAD",
    "LANG",
    "LC_ALL",
    "LD_PRELOAD",
    "MALLOC_ARENA_MAX",
    "MALLOC_TRIM_THRESHOLD_",
    "QUIC_GO_DISABLE_GSO",
    "RUST_BACKTRACE",
    "RUST_LOG",
    "TZ",
    "ZUICITY_ACK_FREQUENCY_THRESHOLD",
    "ZUICITY_CLIENT_CAP",
    "ZUICITY_CLIENT_WORKERS",
    "ZUICITY_DISABLE_GRO",
    "ZUICITY_DISABLE_GSO",
    "ZUICITY_ENABLE_GRO",
    "ZUICITY_ENABLE_GSO",
    "ZUICITY_PLAIN_BATCH_SEGMENTS",
    "ZUICITY_SERVER_CAP",
    "ZUICITY_SERVER_WORKERS",
    "ZUICITY_WORKER_THREADS",
}
METRICS = {
    "tcp_throughput_mbps": ("higher", lambda row: row["tcp_throughput"]["median_mbps"]),
    "tcp_connect_rtt_ms": ("lower", lambda row: row["tcp_connect_rtt"]["median_ms"]),
    "tcp_persistent_rtt_ms": (
        "lower",
        lambda row: row["tcp_persistent_rtt"]["median_ms"],
    ),
    "combined_process_peak_hwm_kib": (
        "lower",
        lambda row: row["resources"]["combined_process_peak_hwm_kib"],
    ),
    "combined_proxy_cpu_seconds": (
        "lower",
        lambda row: row["resources"]["combined_proxy_cpu_seconds"],
    ),
    "payload_mib_per_proxy_cpu_second": (
        "higher",
        lambda row: (
            row["workload"]["throughput_samples"]
            * row["workload"]["throughput_bytes"]
            / (1024 * 1024)
            / row["resources"]["combined_proxy_cpu_seconds"]
        ),
    ),
}


class SuiteError(RuntimeError):
    """Raised when benchmark evidence does not satisfy the suite contract."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SuiteError(f"cannot read JSON {path}: {error}") from error


def write_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: pathlib.Path, value: Any) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def count_udp_segment_traces(trace_paths: Iterable[pathlib.Path]) -> tuple[int, int, int]:
    data_attempts = 0
    successes = 0
    capability_probes = 0
    for path in trace_paths:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                data_send = UDP_SEGMENT_CMSG_PATTERN.search(line)
                capability_probe = UDP_SEGMENT_SETSOCKOPT_PATTERN.search(line)
                if not data_send and not capability_probe:
                    continue
                if data_send:
                    data_attempts += 1
                if capability_probe:
                    capability_probes += 1
                # A successful setsockopt proves a capability probe, not that a
                # segmented data message was sent. Preserve the suite's
                # GSO-present gate by counting only successful sendmsg cmsgs.
                if data_send and SUCCESSFUL_SYSCALL_PATTERN.search(line):
                    successes += 1
    return data_attempts, successes, capability_probes


def resolve_binary_path(
    raw: str, manifest_path: pathlib.Path, allow_unresolved: bool = False
) -> pathlib.Path:
    expanded = os.path.expanduser(os.path.expandvars(raw))
    if "$" in expanded:
        if allow_unresolved:
            return pathlib.Path(expanded)
        raise SuiteError(f"unresolved environment variable in binary path: {raw}")
    path = pathlib.Path(expanded)
    if not path.is_absolute():
        path = manifest_path.parent / path
    return path.resolve()


def load_manifest(path: pathlib.Path, verify_files: bool = True) -> dict[str, Any]:
    manifest = read_json(path)
    if not isinstance(manifest, dict) or manifest.get("schema_version") != SCHEMA_VERSION:
        raise SuiteError(f"manifest schema_version must be {SCHEMA_VERSION}")
    implementations = manifest.get("implementations")
    if not isinstance(implementations, list) or len(implementations) < 2:
        raise SuiteError("manifest must define at least two implementations")

    seen: set[str] = set()
    for implementation in implementations:
        if not isinstance(implementation, dict):
            raise SuiteError("each implementation must be an object")
        identifier = implementation.get("id")
        if not isinstance(identifier, str) or not ID_PATTERN.fullmatch(identifier):
            raise SuiteError(f"invalid implementation id: {identifier!r}")
        if identifier in seen:
            raise SuiteError(f"duplicate implementation id: {identifier}")
        seen.add(identifier)
        for field in ("label", "version", "source", "family"):
            if not isinstance(implementation.get(field), str) or not implementation[field]:
                raise SuiteError(f"{identifier}.{field} must be a non-empty string")

        for role in ("client", "server"):
            binary = implementation.get(role)
            if not isinstance(binary, dict):
                raise SuiteError(f"{identifier}.{role} must be an object")
            expected_hash = binary.get("sha256")
            if not isinstance(expected_hash, str) or not SHA256_PATTERN.fullmatch(expected_hash):
                raise SuiteError(f"{identifier}.{role}.sha256 must be lowercase SHA256")
            if not isinstance(binary.get("path"), str) or not binary["path"]:
                raise SuiteError(f"{identifier}.{role}.path must be a non-empty string")
            resolved = resolve_binary_path(
                binary["path"], path, allow_unresolved=not verify_files
            )
            binary["resolved_path"] = str(resolved)
            if verify_files:
                if not resolved.is_file():
                    raise SuiteError(f"binary does not exist: {resolved}")
                actual_hash = sha256_file(resolved)
                if actual_hash != expected_hash:
                    raise SuiteError(
                        f"hash mismatch for {identifier}.{role}: "
                        f"expected {expected_hash}, got {actual_hash}"
                    )

        modes = implementation.get("modes")
        if not isinstance(modes, dict) or set(modes) != set(MODES):
            raise SuiteError(f"{identifier}.modes must contain exactly on and off")
        for mode in MODES:
            mode_config = modes[mode]
            if not isinstance(mode_config, dict):
                raise SuiteError(f"{identifier}.modes.{mode} must be an object")
            expected_trace = "present" if mode == "on" else "absent"
            if mode_config.get("gso_trace") != expected_trace:
                raise SuiteError(
                    f"{identifier}.{mode} gso_trace must be {expected_trace!r}"
                )
            set_values = mode_config.get("set", {})
            unset_values = mode_config.get("unset", [])
            if not isinstance(set_values, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in set_values.items()
            ):
                raise SuiteError(f"{identifier}.{mode}.set must map strings to strings")
            if not isinstance(unset_values, list) or not all(
                isinstance(value, str) for value in unset_values
            ):
                raise SuiteError(f"{identifier}.{mode}.unset must be a string list")
            overlap = set(set_values).intersection(unset_values)
            if overlap:
                raise SuiteError(f"{identifier}.{mode} sets and unsets {sorted(overlap)}")
            probe_accept_error = mode_config.get(
                "probe_accept_trace_with_driver_error", False
            )
            if not isinstance(probe_accept_error, bool):
                raise SuiteError(
                    f"{identifier}.{mode}.probe_accept_trace_with_driver_error "
                    "must be a boolean"
                )

            preloads = mode_config.get("preload", {})
            if not isinstance(preloads, dict) or not set(preloads).issubset(
                {"client", "server"}
            ):
                raise SuiteError(
                    f"{identifier}.{mode}.preload may contain only client and server"
                )
            for role, preload in preloads.items():
                if not isinstance(preload, dict):
                    raise SuiteError(
                        f"{identifier}.{mode}.preload.{role} must be an object"
                    )
                expected_hash = preload.get("sha256")
                if not isinstance(expected_hash, str) or not SHA256_PATTERN.fullmatch(
                    expected_hash
                ):
                    raise SuiteError(
                        f"{identifier}.{mode}.preload.{role}.sha256 must be lowercase SHA256"
                    )
                if not isinstance(preload.get("path"), str) or not preload["path"]:
                    raise SuiteError(
                        f"{identifier}.{mode}.preload.{role}.path must be a non-empty string"
                    )
                resolved = resolve_binary_path(
                    preload["path"], path, allow_unresolved=not verify_files
                )
                preload["resolved_path"] = str(resolved)
                if verify_files:
                    if not resolved.is_file():
                        raise SuiteError(f"preload does not exist: {resolved}")
                    actual_hash = sha256_file(resolved)
                    if actual_hash != expected_hash:
                        raise SuiteError(
                            f"hash mismatch for {identifier}.{mode}.preload.{role}: "
                            f"expected {expected_hash}, got {actual_hash}"
                        )

    reference = manifest.get("reference")
    if reference not in seen:
        raise SuiteError("manifest reference must name an implementation")
    return manifest


def treatments(manifest: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (implementation["id"], mode)
        for implementation in manifest["implementations"]
        for mode in MODES
    ]


def williams_sequences(items: list[Any]) -> list[list[Any]]:
    """Return an even-treatment Williams square balanced for first carryover."""
    count = len(items)
    if count < 2 or count % 2:
        raise SuiteError("Williams scheduling requires an even treatment count")
    base = [0]
    for index in range(1, count):
        base.append((index + 1) // 2 if index % 2 else count - index // 2)
    return [
        [items[(item + shift) % count] for item in base]
        for shift in range(count)
    ]


def build_schedule(
    manifest: dict[str, Any], blocks: int, max_rotations: int | None = None
) -> list[dict[str, Any]]:
    if blocks < 1:
        raise SuiteError("blocks must be positive")
    sequences = williams_sequences(treatments(manifest))
    rotations: list[dict[str, Any]] = []
    number = 0
    for block in range(1, blocks + 1):
        block_sequences = sequences if block % 2 else list(reversed(sequences))
        for block_rotation, sequence in enumerate(block_sequences, 1):
            number += 1
            rotations.append(
                {
                    "rotation": number,
                    "block": block,
                    "block_rotation": block_rotation,
                    "treatments": [
                        {
                            "position": position,
                            "implementation": treatment[0],
                            "mode": treatment[1],
                        }
                        for position, treatment in enumerate(sequence, 1)
                    ],
                }
            )
    return rotations[:max_rotations] if max_rotations is not None else rotations


def validate_complete_schedule(schedule: list[dict[str, Any]]) -> dict[str, Any]:
    if not schedule:
        raise SuiteError("schedule is empty")
    sequences = [
        [
            (entry["implementation"], entry["mode"])
            for entry in rotation["treatments"]
        ]
        for rotation in schedule
    ]
    treatment_set = set(sequences[0])
    if any(set(sequence) != treatment_set or len(sequence) != len(treatment_set) for sequence in sequences):
        raise SuiteError("every rotation must contain every treatment exactly once")
    positions = collections.Counter()
    carryover = collections.Counter()
    for sequence in sequences:
        for position, treatment in enumerate(sequence):
            positions[(treatment, position)] += 1
        carryover.update(zip(sequence, sequence[1:]))
    position_values = {
        positions[(treatment, position)]
        for treatment in treatment_set
        for position in range(len(treatment_set))
    }
    expected_pairs = {
        (left, right) for left in treatment_set for right in treatment_set if left != right
    }
    pair_values = {carryover[pair] for pair in expected_pairs}
    return {
        "treatments": len(treatment_set),
        "rotations": len(sequences),
        "position_balanced": len(position_values) == 1,
        "first_order_carryover_balanced": len(pair_values) == 1,
        "position_replications": sorted(position_values),
        "carryover_replications": sorted(pair_values),
    }


def parse_cpu_set(value: str) -> set[int]:
    cpus: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if not part:
            raise SuiteError(f"invalid CPU list: {value!r}")
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if end < start:
                raise SuiteError(f"invalid CPU range: {part}")
            cpus.update(range(start, end + 1))
        else:
            cpus.add(int(part))
    return cpus


def read_cpu_counters() -> dict[int, tuple[int, int]]:
    counters: dict[int, tuple[int, int]] = {}
    try:
        lines = pathlib.Path("/proc/stat").read_text(encoding="ascii").splitlines()
    except OSError as error:
        raise SuiteError(f"cannot read /proc/stat: {error}") from error
    for line in lines:
        fields = line.split()
        if not fields or not re.fullmatch(r"cpu[0-9]+", fields[0]):
            continue
        values = [int(value) for value in fields[1:9]]
        total = sum(values)
        idle = values[3] + values[4]
        counters[int(fields[0][3:])] = (total, idle)
    return counters


def cpu_busy_percent(
    before: dict[int, tuple[int, int]],
    after: dict[int, tuple[int, int]],
    selected: Iterable[int] | None = None,
) -> float | None:
    cpus = set(before).intersection(after)
    if selected is not None:
        cpus.intersection_update(selected)
    total_delta = sum(after[cpu][0] - before[cpu][0] for cpu in cpus)
    idle_delta = sum(after[cpu][1] - before[cpu][1] for cpu in cpus)
    if total_delta <= 0:
        return None
    return round(100 * (total_delta - idle_delta) / total_delta, 3)


def wait_for_idle(max_busy: float, timeout_seconds: float) -> float:
    deadline = time.monotonic() + timeout_seconds
    last = 100.0
    while True:
        before = read_cpu_counters()
        time.sleep(1.0)
        after = read_cpu_counters()
        last = cpu_busy_percent(before, after) or 0.0
        if last <= max_busy:
            return last
        if time.monotonic() >= deadline:
            raise SuiteError(
                f"host idle gate timed out: {last:.2f}% busy exceeds {max_busy:.2f}%"
            )


def read_frequency_ratios(cpus: set[int]) -> list[float]:
    ratios: list[float] = []
    for cpu in sorted(cpus):
        root = pathlib.Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
        try:
            current = int((root / "scaling_cur_freq").read_text().strip())
            maximum_path = root / "cpuinfo_max_freq"
            if not maximum_path.exists():
                maximum_path = root / "scaling_max_freq"
            maximum = int(maximum_path.read_text().strip())
        except (OSError, ValueError):
            continue
        if maximum > 0:
            ratios.append(current / maximum)
    return ratios


def read_temperatures_c() -> list[float]:
    values: list[float] = []
    paths = glob.glob("/sys/class/thermal/thermal_zone*/temp")
    paths += glob.glob("/sys/class/hwmon/hwmon*/temp*_input")
    for raw_path in paths:
        try:
            raw = float(pathlib.Path(raw_path).read_text().strip())
        except (OSError, ValueError):
            continue
        value = raw / 1000 if raw > 200 else raw
        if -20 <= value <= 150:
            values.append(value)
    return values


class HostMonitor:
    def __init__(self, benchmark_cpus: set[int]):
        self.benchmark_cpus = benchmark_cpus
        self.before: dict[int, tuple[int, int]] = {}
        self.after: dict[int, tuple[int, int]] = {}
        self.frequency_ratios: list[float] = []
        self.temperatures: list[float] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample, daemon=True)

    def _sample(self) -> None:
        while not self._stop.wait(0.25):
            self.frequency_ratios.extend(read_frequency_ratios(self.benchmark_cpus))
            self.temperatures.extend(read_temperatures_c())

    def __enter__(self) -> HostMonitor:
        self.before = read_cpu_counters()
        self._thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._stop.set()
        self._thread.join()
        self.frequency_ratios.extend(read_frequency_ratios(self.benchmark_cpus))
        self.temperatures.extend(read_temperatures_c())
        self.after = read_cpu_counters()

    def result(self) -> dict[str, Any]:
        all_cpus = set(self.before).intersection(self.after)
        background_cpus = all_cpus - self.benchmark_cpus
        frequency = None
        if self.frequency_ratios:
            frequency = {
                "samples": len(self.frequency_ratios),
                "min_ratio": round(min(self.frequency_ratios), 6),
                "median_ratio": round(statistics.median(self.frequency_ratios), 6),
                "max_ratio": round(max(self.frequency_ratios), 6),
            }
        thermal = None
        if self.temperatures:
            thermal = {
                "samples": len(self.temperatures),
                "min_c": round(min(self.temperatures), 3),
                "max_c": round(max(self.temperatures), 3),
            }
        return {
            "all_cpu_busy_percent": cpu_busy_percent(self.before, self.after),
            "background_cpu_busy_percent": (
                cpu_busy_percent(self.before, self.after, background_cpus)
                if background_cpus
                else None
            ),
            "background_cpu_count": len(background_cpus),
            "frequency": frequency,
            "thermal": thermal,
        }


def evaluate_quality(
    monitor: dict[str, Any],
    pre_row_busy: float,
    max_background_busy: float,
    min_frequency_ratio: float,
    max_temperature_c: float,
) -> dict[str, Any]:
    reasons: list[str] = []
    background = monitor["background_cpu_busy_percent"]
    if background is not None and background > max_background_busy:
        reasons.append(
            f"background_cpu_busy:{background:.3f}>{max_background_busy:.3f}"
        )
    frequency = monitor["frequency"]
    if frequency is not None and frequency["median_ratio"] < min_frequency_ratio:
        reasons.append(
            f"cpu_frequency_ratio:{frequency['median_ratio']:.6f}<{min_frequency_ratio:.6f}"
        )
    thermal = monitor["thermal"]
    if thermal is not None and thermal["max_c"] > max_temperature_c:
        reasons.append(f"temperature:{thermal['max_c']:.3f}>{max_temperature_c:.3f}")
    return {
        "accepted": not reasons,
        "rejection_reasons": reasons,
        "pre_row_cpu_busy_percent": pre_row_busy,
        "during_row": monitor,
        "monitor_availability": {
            "background_cpu": background is not None,
            "frequency": frequency is not None,
            "thermal": thermal is not None,
        },
    }


def implementation_by_id(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in manifest["implementations"]}


def clean_environment(
    manifest: dict[str, Any], implementation: dict[str, Any], mode: str
) -> dict[str, str]:
    environment = os.environ.copy()
    controlled = set(CONTROLLED_ENV)
    for item in manifest["implementations"]:
        for item_mode in MODES:
            controlled.update(item["modes"][item_mode].get("set", {}))
            controlled.update(item["modes"][item_mode].get("unset", []))
    for key in controlled:
        environment.pop(key, None)
    environment.update({"LANG": "C", "LC_ALL": "C", "TZ": "UTC"})
    environment.update(implementation["modes"][mode].get("set", {}))
    for key in implementation["modes"][mode].get("unset", []):
        environment.pop(key, None)
    return environment


def stage_binaries(
    manifest: dict[str, Any], stage_root: pathlib.Path
) -> dict[str, dict[str, Any]]:
    staged: dict[str, dict[str, Any]] = {}
    for implementation in manifest["implementations"]:
        target_dir = stage_root / implementation["id"]
        target_dir.mkdir()
        staged[implementation["id"]] = {"preload": {mode: {} for mode in MODES}}
        for role in ("client", "server"):
            source = pathlib.Path(implementation[role]["resolved_path"])
            target = target_dir / role
            shutil.copyfile(source, target)
            target.chmod(0o755)
            actual_hash = sha256_file(target)
            if actual_hash != implementation[role]["sha256"]:
                raise SuiteError(f"staged {implementation['id']}.{role} hash changed")
            staged[implementation["id"]][role] = target
        for mode in MODES:
            for role, preload in implementation["modes"][mode].get(
                "preload", {}
            ).items():
                source = pathlib.Path(preload["resolved_path"])
                target = target_dir / f"{mode}-{role}-preload.so"
                shutil.copyfile(source, target)
                target.chmod(0o644)
                if sha256_file(target) != preload["sha256"]:
                    raise SuiteError(
                        f"staged {implementation['id']}.{mode}.preload.{role} hash changed"
                    )
                staged[implementation["id"]]["preload"][mode][role] = target
    return staged


def run_harness(
    harness: pathlib.Path,
    implementation: dict[str, Any],
    mode: str,
    staged: dict[str, Any],
    output_dir: pathlib.Path,
    tag: str,
    cpus: str,
    workload: dict[str, int | float],
    trace_gso: str,
    timeout_seconds: int,
    manifest: dict[str, Any],
    role_cpus: dict[str, str] | None = None,
    allow_nonzero: bool = False,
) -> dict[str, Any]:
    command = []
    if cpus:
        command.extend(("taskset", "-c", cpus))
    command.extend([
        "timeout",
        "--signal=TERM",
        "--kill-after=15s",
        f"{timeout_seconds}s",
        "bash",
        str(harness),
        "--tag",
        tag,
        "--client",
        str(staged["client"]),
        "--server",
        str(staged["server"]),
        "--out-dir",
        str(output_dir),
        "--rtt-samples",
        str(workload["rtt_samples"]),
        "--throughput-samples",
        str(workload["throughput_samples"]),
        "--throughput-bytes",
        str(workload["throughput_bytes"]),
        "--warmup-transfers",
        str(workload["warmup_transfers"]),
        "--timeout-seconds",
        str(workload["sample_timeout_seconds"]),
        "--trace-gso",
        trace_gso,
    ])
    if cpus:
        command.extend(("--cpus", cpus))
    if role_cpus:
        for role in ("server", "client", "driver", "echo"):
            if role_cpus.get(role):
                command.extend((f"--{role}-cpus", role_cpus[role]))
    environment = clean_environment(manifest, implementation, mode)
    for role, path in staged.get("preload", {}).get(mode, {}).items():
        environment[f"BENCH_{role.upper()}_PRELOAD"] = str(path)
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=timeout_seconds + 30,
    )
    capture = output_dir / "captures" / tag
    if capture.exists():
        (capture / "orchestrator.stderr").write_text(
            completed.stderr, encoding="utf-8"
        )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise SuiteError(
            f"{tag} emitted {len(lines)} JSON lines (exit {completed.returncode})"
        )
    try:
        row = json.loads(lines[0])
    except json.JSONDecodeError as error:
        raise SuiteError(f"{tag} emitted invalid JSON: {error}") from error
    if row.get("tag") != tag:
        raise SuiteError(f"{tag} result tag mismatch")
    row["harness_exit_status"] = completed.returncode
    if completed.returncode != 0 and not allow_nonzero:
        raise SuiteError(
            f"{tag} failed with exit {completed.returncode}: "
            f"errors={row.get('errors')} trace={row.get('gso_trace')}"
        )
    return row


def assert_row(row: dict[str, Any], workload: dict[str, int | float]) -> None:
    if row.get("errors") != [] or row.get("driver_exit_status") != 0:
        raise SuiteError(f"invalid row {row.get('tag')}: {row.get('errors')}")
    expected = {
        "tcp_connect_rtt": workload["rtt_samples"],
        "tcp_persistent_rtt": workload["rtt_samples"],
        "tcp_throughput": workload["throughput_samples"],
    }
    for metric, count in expected.items():
        if row.get(metric, {}).get("n") != count:
            raise SuiteError(f"{row.get('tag')} has wrong {metric} sample count")
    if row["resources"]["combined_proxy_cpu_seconds"] <= 0:
        raise SuiteError(f"{row.get('tag')} has no proxy CPU accounting")


def median(values: list[float]) -> float:
    return float(statistics.median(values))


def exact_sign_test_one_sided(wins: int, losses: int) -> float | None:
    count = wins + losses
    if count == 0:
        return None
    return sum(math.comb(count, value) for value in range(wins, count + 1)) / (2**count)


def descriptive(values: list[float]) -> dict[str, Any]:
    mean = statistics.mean(values)
    deviation = statistics.stdev(values) if len(values) > 1 else 0.0
    return {
        "n_rotation_rows": len(values),
        "median": median(values),
        "mean": mean,
        "min": min(values),
        "max": max(values),
        "cv_percent": 100 * deviation / mean if mean else None,
        "rotation_values": values,
    }


def paired_comparison(
    numerator: dict[int, float], denominator: dict[int, float], direction: str
) -> dict[str, Any]:
    rotations = sorted(set(numerator).intersection(denominator))
    if not rotations:
        raise SuiteError("paired comparison has no common rotations")
    ratios = [numerator[index] / denominator[index] for index in rotations]
    changes = [(ratio - 1) * 100 for ratio in ratios]
    if direction == "higher":
        wins = sum(ratio > 1 for ratio in ratios)
        losses = sum(ratio < 1 for ratio in ratios)
    else:
        wins = sum(ratio < 1 for ratio in ratios)
        losses = sum(ratio > 1 for ratio in ratios)
    ties = len(ratios) - wins - losses
    return {
        "paired_rotations": rotations,
        "numerator_median": median(list(numerator.values())),
        "denominator_median": median(list(denominator.values())),
        "aggregate_change_percent": (
            median(list(numerator.values())) / median(list(denominator.values())) - 1
        )
        * 100,
        "paired_ratio_median": median(ratios),
        "paired_change_percent_median": median(changes),
        "paired_ratios": ratios,
        "wins": wins,
        "losses": losses,
        "ties": ties,
        "exact_sign_test_one_sided_p": exact_sign_test_one_sided(wins, losses),
        "better_direction": direction,
    }


def summarize_rows(
    rows: list[dict[str, Any]], manifest: dict[str, Any]
) -> dict[str, Any]:
    if not rows:
        raise SuiteError("cannot summarize empty results")
    implementation_ids = [item["id"] for item in manifest["implementations"]]
    expected_treatments = {(item, mode) for item in implementation_ids for mode in MODES}
    by_rotation: dict[int, dict[tuple[str, str], dict[str, Any]]] = {}
    for row in rows:
        key = (row["implementation"], row["mode"])
        if key not in expected_treatments:
            raise SuiteError(f"unexpected treatment in row: {key}")
        rotation = int(row["rotation"])
        if key in by_rotation.setdefault(rotation, {}):
            raise SuiteError(f"duplicate treatment {key} in rotation {rotation}")
        by_rotation[rotation][key] = row
    if any(set(rotation_rows) != expected_treatments for rotation_rows in by_rotation.values()):
        raise SuiteError("each accepted rotation must contain every treatment")

    metric_rows: dict[str, dict[str, dict[str, dict[int, float]]]] = {}
    arms: dict[str, Any] = {}
    for identifier in implementation_ids:
        arms[identifier] = {}
        for mode in MODES:
            arms[identifier][mode] = {"metrics": {}}
            for metric, (direction, getter) in METRICS.items():
                values = {
                    rotation: float(getter(rotation_rows[(identifier, mode)]))
                    for rotation, rotation_rows in sorted(by_rotation.items())
                }
                metric_rows.setdefault(metric, {}).setdefault(identifier, {})[mode] = values
                arms[identifier][mode]["metrics"][metric] = {
                    "better_direction": direction,
                    **descriptive(list(values.values())),
                }

    reference = manifest["reference"]
    comparisons: dict[str, Any] = {}
    for mode in MODES:
        comparisons[mode] = {}
        for identifier in implementation_ids:
            if identifier == reference:
                continue
            comparisons[mode][identifier] = {}
            for metric, (direction, _getter) in METRICS.items():
                comparisons[mode][identifier][metric] = paired_comparison(
                    metric_rows[metric][reference][mode],
                    metric_rows[metric][identifier][mode],
                    direction,
                )

    gso_uplift: dict[str, Any] = {}
    for identifier in implementation_ids:
        gso_uplift[identifier] = {}
        for metric, (direction, _getter) in METRICS.items():
            gso_uplift[identifier][metric] = paired_comparison(
                metric_rows[metric][identifier]["on"],
                metric_rows[metric][identifier]["off"],
                direction,
            )

    monitor_availability = {
        monitor: all(
            row["quality"]["monitor_availability"].get(monitor, False) for row in rows
        )
        for monitor in ("background_cpu", "frequency", "thermal")
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "inference_unit": "rotation_row",
        "pooled_transfer_samples_used_for_inference": False,
        "reference": reference,
        "rotations": len(by_rotation),
        "row_count": len(rows),
        "throughput_transfer_count": sum(
            row["tcp_throughput"]["n"] for row in rows
        ),
        "quality": {
            "all_rows_accepted": all(row["quality"]["accepted"] for row in rows),
            "monitor_availability_all_rows": monitor_availability,
        },
        "arms": arms,
        "reference_comparisons": comparisons,
        "gso_on_vs_off": gso_uplift,
    }


def render_summary_markdown(summary: dict[str, Any], manifest: dict[str, Any]) -> str:
    labels = {item["id"]: item["label"] for item in manifest["implementations"]}
    lines = [
        "# TCP GSO benchmark summary",
        "",
        f"Inference unit: rotation-level row median. Rotations: {summary['rotations']}. ",
        "Transfer samples are retained as raw evidence but are not treated as independent replicates.",
        "",
        "| Implementation | GSO | Throughput median (Mbps) | Combined HWM (KiB) | Proxy CPU (s) |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for identifier, modes in summary["arms"].items():
        for mode in MODES:
            metrics = modes[mode]["metrics"]
            lines.append(
                f"| {labels[identifier]} | {mode} | "
                f"{metrics['tcp_throughput_mbps']['median']:.2f} | "
                f"{metrics['combined_process_peak_hwm_kib']['median']:.0f} | "
                f"{metrics['combined_proxy_cpu_seconds']['median']:.3f} |"
            )
    lines.extend(("", f"Reference: `{summary['reference']}`.", ""))
    for mode in MODES:
        lines.extend(
            (
                f"## GSO {mode}",
                "",
                "| Comparator | Paired throughput change | Wins-losses-ties | Exact one-sided sign p |",
                "| --- | ---: | ---: | ---: |",
            )
        )
        for identifier, metrics in summary["reference_comparisons"][mode].items():
            throughput = metrics["tcp_throughput_mbps"]
            p_value = throughput["exact_sign_test_one_sided_p"]
            p_text = "n/a" if p_value is None else f"{p_value:.6g}"
            lines.append(
                f"| {labels[identifier]} | "
                f"{throughput['paired_change_percent_median']:+.2f}% | "
                f"{throughput['wins']}-{throughput['losses']}-{throughput['ties']} | "
                f"{p_text} |"
            )
        lines.append("")
    return "\n".join(lines)


def host_metadata(cpus: str) -> dict[str, Any]:
    def command_output(command: list[str]) -> str | None:
        try:
            completed = subprocess.run(
                command, check=False, capture_output=True, text=True, timeout=10
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return completed.stdout if completed.returncode == 0 else None

    governors: dict[str, str] = {}
    for path in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"):
        try:
            governors[pathlib.Path(path).parts[-3]] = pathlib.Path(path).read_text().strip()
        except OSError:
            pass
    return {
        "recorded_at_utc": utc_now(),
        "platform": platform.platform(),
        "uname": list(platform.uname()),
        "python": platform.python_version(),
        "cpu_affinity": cpus or None,
        "logical_cpu_count": os.cpu_count(),
        "cpu_governors": governors,
        "lscpu": command_output(["lscpu"]),
        "os_release": (
            pathlib.Path("/etc/os-release").read_text(encoding="utf-8")
            if pathlib.Path("/etc/os-release").exists()
            else None
        ),
        "thermal_sensor_count": len(read_temperatures_c()),
    }


def capture_versions(
    manifest: dict[str, Any], staged: dict[str, dict[str, Any]], meta: pathlib.Path
) -> None:
    version_dir = meta / "versions"
    version_dir.mkdir()
    for implementation in manifest["implementations"]:
        for role in ("client", "server"):
            outputs: list[str] = []
            for arguments in (["--version"], ["version"]):
                try:
                    completed = subprocess.run(
                        [str(staged[implementation["id"]][role]), *arguments],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                except (OSError, subprocess.TimeoutExpired) as error:
                    outputs.append(f"command={arguments!r} error={error}\n")
                    continue
                outputs.append(
                    f"command={arguments!r} exit={completed.returncode}\n"
                    f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}\n"
                )
                if completed.returncode == 0:
                    break
            (version_dir / f"{implementation['id']}-{role}.txt").write_text(
                "".join(outputs), encoding="utf-8"
            )


def run_campaign(args: argparse.Namespace) -> pathlib.Path:
    if os.name != "posix" or not pathlib.Path("/proc/stat").exists():
        raise SuiteError("campaign execution requires Linux")
    if os.geteuid() != 0:
        raise SuiteError("campaign execution requires root for network namespaces")
    required_commands = {"bash", "ip", "openssl", "python3", "timeout"}
    if args.cpus:
        required_commands.add("taskset")
    if not args.skip_gso_probes:
        required_commands.add("strace")
    missing_commands = sorted(
        command for command in required_commands if shutil.which(command) is None
    )
    if missing_commands:
        raise SuiteError(f"missing required commands: {', '.join(missing_commands)}")
    namespace_list = subprocess.run(
        ["ip", "netns", "list"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    stale_namespaces = [
        line.split()[0]
        for line in namespace_list.stdout.splitlines()
        if line.startswith("zuicity-bench-")
    ]
    if stale_namespaces:
        raise SuiteError(
            "stale suite namespaces must be inspected before running: "
            + ", ".join(stale_namespaces)
        )
    manifest_path = pathlib.Path(args.manifest).resolve()
    manifest = load_manifest(manifest_path, verify_files=True)
    output_dir = pathlib.Path(args.out_dir).resolve()
    if output_dir.exists():
        raise SuiteError(f"refusing to overwrite output directory: {output_dir}")
    output_dir.mkdir(parents=True)
    (output_dir / "captures").mkdir()
    (output_dir / "meta").mkdir()
    results_path = output_dir / "results.jsonl"
    rejected_path = output_dir / "rejected.jsonl"
    probes_path = output_dir / "probes.jsonl"
    results_path.touch()
    rejected_path.touch()
    probes_path.touch()

    profile_defaults = {
        "release": {
            "blocks": 2,
            "rtt_samples": 60,
            "throughput_samples": 100,
            "throughput_bytes": 4 * 1024 * 1024,
            "warmup_transfers": 5,
            "max_rotations": None,
        },
        "standard": {
            "blocks": 1,
            "rtt_samples": 60,
            "throughput_samples": 100,
            "throughput_bytes": 4 * 1024 * 1024,
            "warmup_transfers": 5,
            "max_rotations": None,
        },
        "smoke": {
            "blocks": 1,
            "rtt_samples": 2,
            "throughput_samples": 3,
            "throughput_bytes": 1024 * 1024,
            "warmup_transfers": 1,
            "max_rotations": 1,
        },
    }[args.profile]
    override_values = {
        "blocks": args.blocks,
        "rtt_samples": args.rtt_samples,
        "throughput_samples": args.throughput_samples,
        "throughput_bytes": args.throughput_bytes,
        "warmup_transfers": args.warmup_transfers,
    }
    defaults = profile_defaults | {
        key: value
        for key, value in override_values.items()
        if value is not None
    }
    if args.profile != "smoke" and not args.cpus:
        raise SuiteError("standard and release campaigns require --cpus")
    cpu_set = parse_cpu_set(args.cpus) if args.cpus else set(read_cpu_counters())
    available_cpus = set(read_cpu_counters())
    if not cpu_set.issubset(available_cpus):
        raise SuiteError(f"CPU affinity contains unavailable CPUs: {cpu_set - available_cpus}")

    schedule = build_schedule(
        manifest,
        int(defaults["blocks"]),
        defaults["max_rotations"],
    )
    schedule_validation = validate_complete_schedule(schedule)
    canonical = (
        not any(value is not None for value in override_values.values())
        and defaults["max_rotations"] is None
        and schedule_validation["position_balanced"]
        and schedule_validation["first_order_carryover_balanced"]
    )
    workload = {
        "rtt_samples": int(defaults["rtt_samples"]),
        "throughput_samples": int(defaults["throughput_samples"]),
        "throughput_bytes": int(defaults["throughput_bytes"]),
        "warmup_transfers": int(defaults["warmup_transfers"]),
        "sample_timeout_seconds": args.sample_timeout_seconds,
    }
    method = {
        "schema_version": SCHEMA_VERSION,
        "started_at_utc": utc_now(),
        "profile": args.profile,
        "profile_overridden": any(
            value is not None for value in override_values.values()
        ),
        "canonical_balanced_campaign": canonical,
        "design": "even-treatment Williams square",
        "schedule_validation": schedule_validation,
        "workload": workload,
        "gso_probe_workload": {
            "rtt_samples": 2,
            "throughput_samples": 1,
            "throughput_bytes": min(int(defaults["throughput_bytes"]), 64 * 1024),
            "warmup_transfers": 0,
            "sample_timeout_seconds": args.sample_timeout_seconds,
        },
        "quality_gates": {
            "max_pre_row_cpu_busy_percent": args.max_pre_row_busy,
            "idle_wait_timeout_seconds": args.idle_wait_seconds,
            "max_background_cpu_busy_percent": args.max_background_busy,
            "min_median_frequency_ratio": args.min_frequency_ratio,
            "max_temperature_c": args.max_temperature_c,
            "max_row_attempts": args.max_row_attempts,
        },
        "role_cpu_affinity": {
            "server": args.server_cpus or args.cpus or None,
            "client": args.client_cpus or args.cpus or None,
            "driver": args.driver_cpus or args.cpus or None,
            "echo": args.echo_cpus or args.cpus or None,
            "monitored_union": args.cpus or None,
        },
        "environment_policy": "controlled benchmark variables removed, then manifest mode set applied",
        "inference_unit": "rotation_row",
        "pooled_transfer_samples_are_independent": False,
    }
    write_json(output_dir / "meta" / "method.json", method)
    write_json(output_dir / "meta" / "schedule.json", schedule)
    write_json(output_dir / "meta" / "host.json", host_metadata(args.cpus))
    resolved_manifest = json.loads(json.dumps(manifest))
    write_json(output_dir / "meta" / "resolved-manifest.json", resolved_manifest)

    here = pathlib.Path(__file__).resolve().parent
    harness = here / "bench-one-tcp.sh"
    helpers = [pathlib.Path(__file__).resolve(), harness, here / "tcp-driver.py", here / "echo-server.py"]
    (output_dir / "meta" / "harness.sha256").write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in helpers),
        encoding="ascii",
    )
    artifact_hashes = []
    for implementation in manifest["implementations"]:
        for role in ("client", "server"):
            artifact_hashes.append(
                f"{implementation[role]['sha256']}  {implementation['id']}/{role}\n"
            )
        for mode in MODES:
            for role, preload in implementation["modes"][mode].get(
                "preload", {}
            ).items():
                artifact_hashes.append(
                    f"{preload['sha256']}  "
                    f"{implementation['id']}/{mode}/{role}-preload.so\n"
                )
    (output_dir / "meta" / "binaries.sha256").write_text(
        "".join(artifact_hashes), encoding="ascii"
    )

    stage_root = pathlib.Path(tempfile.mkdtemp(prefix="zuicity-tcp-gso-bin."))
    try:
        staged = stage_binaries(manifest, stage_root)
        capture_versions(manifest, staged, output_dir / "meta")
        implementations = implementation_by_id(manifest)

        if not args.skip_gso_probes:
            probe_workload = method["gso_probe_workload"]
            for implementation in manifest["implementations"]:
                for mode in MODES:
                    tag = f"probe-{implementation['id']}-{mode}"
                    wait_for_idle(args.max_pre_row_busy, args.idle_wait_seconds)
                    row = run_harness(
                        harness,
                        implementation,
                        mode,
                        staged[implementation["id"]],
                        output_dir,
                        tag,
                        args.cpus,
                        probe_workload,
                        implementation["modes"][mode]["gso_trace"],
                        args.row_timeout_seconds,
                        manifest,
                        {
                            "server": args.server_cpus,
                            "client": args.client_cpus,
                            "driver": args.driver_cpus,
                            "echo": args.echo_cpus,
                        },
                        implementation["modes"][mode].get(
                            "probe_accept_trace_with_driver_error", False
                        ),
                    )
                    if not row.get("gso_trace", {}).get("passed"):
                        raise SuiteError(f"GSO trace validation failed for {tag}")
                    row.update(
                        {
                            "implementation": implementation["id"],
                            "implementation_version": implementation["version"],
                            "mode": mode,
                            "binary_sha256": {
                                role: implementation[role]["sha256"]
                                for role in ("client", "server")
                            },
                        }
                    )
                    append_jsonl(probes_path, row)

        accepted_rows: list[dict[str, Any]] = []
        for rotation in schedule:
            rotation_rows: list[dict[str, Any]] = []
            for treatment in rotation["treatments"]:
                implementation = implementations[treatment["implementation"]]
                accepted = None
                for attempt in range(1, args.max_row_attempts + 1):
                    tag = (
                        f"r{rotation['rotation']:03d}-p{treatment['position']:02d}-"
                        f"{implementation['id']}-{treatment['mode']}-a{attempt}"
                    )
                    pre_busy = wait_for_idle(
                        args.max_pre_row_busy, args.idle_wait_seconds
                    )
                    with HostMonitor(cpu_set) as host_monitor:
                        row = run_harness(
                            harness,
                            implementation,
                            treatment["mode"],
                            staged[implementation["id"]],
                            output_dir,
                            tag,
                            args.cpus,
                            workload,
                            "skip",
                            args.row_timeout_seconds,
                            manifest,
                            {
                                "server": args.server_cpus,
                                "client": args.client_cpus,
                                "driver": args.driver_cpus,
                                "echo": args.echo_cpus,
                            },
                            True,
                        )
                    quality = evaluate_quality(
                        host_monitor.result(),
                        pre_busy,
                        args.max_background_busy,
                        args.min_frequency_ratio,
                        args.max_temperature_c,
                    )
                    try:
                        assert_row(row, workload)
                    except SuiteError as error:
                        quality["accepted"] = False
                        quality["rejection_reasons"].insert(
                            0, f"row_contract:{error}"
                        )
                    row.update(
                        {
                            "implementation": implementation["id"],
                            "implementation_version": implementation["version"],
                            "mode": treatment["mode"],
                            "rotation": rotation["rotation"],
                            "block": rotation["block"],
                            "block_rotation": rotation["block_rotation"],
                            "position": treatment["position"],
                            "attempt": attempt,
                            "quality": quality,
                            "binary_sha256": {
                                role: implementation[role]["sha256"]
                                for role in ("client", "server")
                            },
                        }
                    )
                    if quality["accepted"]:
                        accepted = row
                        break
                    append_jsonl(rejected_path, row)
                if accepted is None:
                    raise SuiteError(
                        f"quality gates rejected {implementation['id']}-{treatment['mode']} "
                        f"in rotation {rotation['rotation']} {args.max_row_attempts} times"
                    )
                rotation_rows.append(accepted)
            for row in rotation_rows:
                append_jsonl(results_path, row)
                accepted_rows.append(row)

        summary = summarize_rows(accepted_rows, manifest)
        summary["profile"] = args.profile
        summary["canonical_balanced_campaign"] = canonical
        summary["schedule_validation"] = schedule_validation
        summary["rejected_row_count"] = sum(
            1 for line in rejected_path.read_text(encoding="utf-8").splitlines() if line
        )
        write_json(output_dir / "summary.json", summary)
        (output_dir / "summary.md").write_text(
            render_summary_markdown(summary, manifest), encoding="utf-8"
        )
        method["completed_at_utc"] = utc_now()
        write_json(output_dir / "meta" / "method.json", method)
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)
    return output_dir


def read_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise SuiteError(f"invalid JSONL at {path}:{number}: {error}") from error
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate manifest and hashes")
    validate.add_argument("--manifest", required=True)
    validate.add_argument("--skip-files", action="store_true")

    schedule = subparsers.add_parser("schedule", help="print the Williams schedule")
    schedule.add_argument("--manifest", required=True)
    schedule.add_argument("--blocks", type=int, default=1)

    summarize = subparsers.add_parser("summarize", help="summarize existing raw rows")
    summarize.add_argument("--manifest", required=True)
    summarize.add_argument("--results", required=True)
    summarize.add_argument("--output")

    trace_counts = subparsers.add_parser(
        "trace-counts", help="count successful UDP_SEGMENT control messages in strace files"
    )
    trace_counts.add_argument("traces", nargs="+")

    run = subparsers.add_parser("run", help="run a new isolated campaign")
    run.add_argument("--manifest", required=True)
    run.add_argument("--out-dir", required=True)
    run.add_argument("--profile", choices=("release", "standard", "smoke"), default="release")
    run.add_argument("--cpus", default="")
    run.add_argument("--server-cpus", default="")
    run.add_argument("--client-cpus", default="")
    run.add_argument("--driver-cpus", default="")
    run.add_argument("--echo-cpus", default="")
    run.add_argument("--blocks", type=int)
    run.add_argument("--rtt-samples", type=int)
    run.add_argument("--throughput-samples", type=int)
    run.add_argument("--throughput-bytes", type=int)
    run.add_argument("--warmup-transfers", type=int)
    run.add_argument("--sample-timeout-seconds", type=float, default=120.0)
    run.add_argument("--row-timeout-seconds", type=int, default=900)
    run.add_argument("--max-pre-row-busy", type=float, default=20.0)
    run.add_argument("--idle-wait-seconds", type=float, default=60.0)
    run.add_argument("--max-background-busy", type=float, default=20.0)
    run.add_argument("--min-frequency-ratio", type=float, default=0.70)
    run.add_argument("--max-temperature-c", type=float, default=90.0)
    run.add_argument("--max-row-attempts", type=int, default=3)
    run.add_argument("--skip-gso-probes", action="store_true")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "validate":
            manifest = load_manifest(
                pathlib.Path(args.manifest).resolve(), verify_files=not args.skip_files
            )
            print(
                json.dumps(
                    {
                        "valid": True,
                        "implementations": [
                            item["id"] for item in manifest["implementations"]
                        ],
                        "reference": manifest["reference"],
                    },
                    sort_keys=True,
                )
            )
        elif args.command == "schedule":
            manifest = load_manifest(
                pathlib.Path(args.manifest).resolve(), verify_files=False
            )
            schedule = build_schedule(manifest, args.blocks)
            print(
                json.dumps(
                    {
                        "validation": validate_complete_schedule(schedule),
                        "schedule": schedule,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        elif args.command == "summarize":
            manifest = load_manifest(
                pathlib.Path(args.manifest).resolve(), verify_files=False
            )
            summary = summarize_rows(
                read_jsonl(pathlib.Path(args.results).resolve()), manifest
            )
            if args.output:
                write_json(pathlib.Path(args.output), summary)
            else:
                print(json.dumps(summary, indent=2, sort_keys=True))
        elif args.command == "trace-counts":
            attempts, successes, capability_probes = count_udp_segment_traces(
                pathlib.Path(path) for path in args.traces
            )
            print(attempts, successes, capability_probes)
        else:
            output = run_campaign(args)
            print(f"CAMPAIGN_COMPLETE {output}")
        return 0
    except (SuiteError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
