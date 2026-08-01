#!/usr/bin/env python3

import json
import pathlib
import tempfile
import unittest

import tcp_gso_suite as suite


def manifest_with_paths(client: pathlib.Path, server: pathlib.Path):
    client_hash = suite.sha256_file(client)
    server_hash = suite.sha256_file(server)

    def implementation(identifier):
        return {
            "id": identifier,
            "label": identifier,
            "version": "test",
            "source": "unit test",
            "family": "test",
            "client": {"path": str(client), "sha256": client_hash},
            "server": {"path": str(server), "sha256": server_hash},
            "modes": {
                "on": {"set": {"TEST_GSO": "1"}, "unset": [], "gso_trace": "present"},
                "off": {"set": {}, "unset": ["TEST_GSO"], "gso_trace": "absent"},
            },
        }

    return {
        "schema_version": 1,
        "reference": "candidate",
        "implementations": [implementation("candidate"), implementation("comparator")],
    }


def synthetic_row(rotation, implementation, mode, throughput):
    return {
        "rotation": rotation,
        "implementation": implementation,
        "mode": mode,
        "workload": {"throughput_samples": 3, "throughput_bytes": 1024 * 1024},
        "tcp_throughput": {"n": 3, "median_mbps": throughput},
        "tcp_connect_rtt": {"n": 2, "median_ms": 1 / throughput},
        "tcp_persistent_rtt": {"n": 2, "median_ms": 0.5 / throughput},
        "resources": {
            "combined_process_peak_hwm_kib": 1000 / throughput,
            "combined_proxy_cpu_seconds": 100 / throughput,
        },
        "quality": {
            "accepted": True,
            "monitor_availability": {
                "background_cpu": True,
                "frequency": True,
                "thermal": True,
            },
        },
    }


class ManifestTests(unittest.TestCase):
    def test_hashes_are_verified(self):
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = pathlib.Path(raw_directory)
            client = directory / "client"
            server = directory / "server"
            client.write_bytes(b"client")
            server.write_bytes(b"server")
            manifest = manifest_with_paths(client, server)
            path = directory / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            loaded = suite.load_manifest(path)
            self.assertEqual(loaded["reference"], "candidate")

            client.write_bytes(b"changed")
            with self.assertRaisesRegex(suite.SuiteError, "hash mismatch"):
                suite.load_manifest(path)

    def test_mode_trace_expectation_is_strict(self):
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = pathlib.Path(raw_directory)
            client = directory / "client"
            server = directory / "server"
            client.write_bytes(b"client")
            server.write_bytes(b"server")
            manifest = manifest_with_paths(client, server)
            manifest["implementations"][0]["modes"]["off"]["gso_trace"] = "present"
            path = directory / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(suite.SuiteError, "must be 'absent'"):
                suite.load_manifest(path)

    def test_preload_hashes_are_verified(self):
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = pathlib.Path(raw_directory)
            client = directory / "client"
            server = directory / "server"
            preload = directory / "control.so"
            client.write_bytes(b"client")
            server.write_bytes(b"server")
            preload.write_bytes(b"control")
            manifest = manifest_with_paths(client, server)
            manifest["implementations"][0]["modes"]["off"]["preload"] = {
                role: {
                    "path": str(preload),
                    "sha256": suite.sha256_file(preload),
                }
                for role in ("client", "server")
            }
            path = directory / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            suite.load_manifest(path)

            preload.write_bytes(b"changed")
            with self.assertRaisesRegex(suite.SuiteError, "hash mismatch"):
                suite.load_manifest(path)

    def test_probe_driver_error_policy_must_be_boolean(self):
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = pathlib.Path(raw_directory)
            client = directory / "client"
            server = directory / "server"
            client.write_bytes(b"client")
            server.write_bytes(b"server")
            manifest = manifest_with_paths(client, server)
            manifest["implementations"][0]["modes"]["on"][
                "probe_accept_trace_with_driver_error"
            ] = "yes"
            path = directory / "manifest.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(suite.SuiteError, "must be a boolean"):
                suite.load_manifest(path)


class DesignTests(unittest.TestCase):
    def test_williams_square_balances_position_and_carryover(self):
        items = list(range(8))
        schedule = [
            {
                "treatments": [
                    {"implementation": str(value), "mode": "on"}
                    for value in sequence
                ]
            }
            for sequence in suite.williams_sequences(items)
        ]
        validation = suite.validate_complete_schedule(schedule)
        self.assertTrue(validation["position_balanced"])
        self.assertTrue(validation["first_order_carryover_balanced"])
        self.assertEqual(validation["position_replications"], [1])
        self.assertEqual(validation["carryover_replications"], [1])

    def test_partial_schedule_is_not_reported_as_balanced(self):
        schedule = [
            {
                "treatments": [
                    {"implementation": str(value), "mode": "on"}
                    for value in suite.williams_sequences(list(range(4)))[0]
                ]
            }
        ]
        validation = suite.validate_complete_schedule(schedule)
        self.assertFalse(validation["position_balanced"])
        self.assertFalse(validation["first_order_carryover_balanced"])


class TraceTests(unittest.TestCase):
    def test_udp_segment_symbolic_and_numeric_forms_are_counted(self):
        lines = [
            "sendmsg(3, {msg_control=[{cmsg_level=SOL_UDP, "
            "cmsg_type=UDP_SEGMENT, cmsg_data=[1400]}]}, 0) = 15972",
            "sendmsg(3, {msg_control=[{cmsg_level=SOL_UDP, "
            'cmsg_type=0x67, cmsg_data="\\xac\\x05"}]}, 0) = 7260',
            "sendmsg(3, {msg_control=[{cmsg_level=IPPROTO_UDP, "
            "cmsg_type=103, cmsg_data=[1400]}]}, 0) = -1 EIO (Input/output error)",
            "sendmsg(3, {msg_control=[{cmsg_level=SOL_IP, "
            "cmsg_type=0x67, cmsg_data=[1400]}]}, 0) = 1400",
        ]
        with tempfile.TemporaryDirectory() as raw_directory:
            trace = pathlib.Path(raw_directory) / "client.strace.1"
            trace.write_text("\n".join(lines) + "\n", encoding="utf-8")
            attempts, successes = suite.count_udp_segment_traces([trace])
        self.assertEqual(attempts, 3)
        self.assertEqual(successes, 2)


class SummaryTests(unittest.TestCase):
    def test_summary_uses_rotation_rows_for_inference(self):
        manifest = {
            "reference": "candidate",
            "implementations": [
                {"id": "candidate", "label": "candidate"},
                {"id": "comparator", "label": "comparator"},
            ],
        }
        rows = []
        for rotation in range(1, 5):
            rows.extend(
                (
                    synthetic_row(rotation, "candidate", "on", 200 + rotation),
                    synthetic_row(rotation, "candidate", "off", 150 + rotation),
                    synthetic_row(rotation, "comparator", "on", 100 + rotation),
                    synthetic_row(rotation, "comparator", "off", 90 + rotation),
                )
            )
        summary = suite.summarize_rows(rows, manifest)
        comparison = summary["reference_comparisons"]["on"]["comparator"][
            "tcp_throughput_mbps"
        ]
        self.assertEqual(summary["rotations"], 4)
        self.assertEqual(summary["throughput_transfer_count"], 48)
        self.assertFalse(summary["pooled_transfer_samples_used_for_inference"])
        self.assertEqual(comparison["wins"], 4)
        self.assertEqual(comparison["exact_sign_test_one_sided_p"], 0.0625)

    def test_incomplete_rotation_is_rejected(self):
        manifest = {
            "reference": "candidate",
            "implementations": [
                {"id": "candidate", "label": "candidate"},
                {"id": "comparator", "label": "comparator"},
            ],
        }
        rows = [synthetic_row(1, "candidate", "on", 200)]
        with self.assertRaisesRegex(suite.SuiteError, "every treatment"):
            suite.summarize_rows(rows, manifest)


if __name__ == "__main__":
    unittest.main()
