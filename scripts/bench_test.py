import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bench


class MetadataTest(unittest.TestCase):
    def test_socat_version_uses_version_line(self) -> None:
        output = (
            "socat by Gerhard Rieger and contributors - see www.dest-unreach.org\n"
            "socat version 1.8.1.3\n"
            "features:\n"
        )
        with mock.patch.object(bench, "run_cmd", return_value=output):
            self.assertEqual(bench.socat_version(["socat", "-V"]), "socat version 1.8.1.3")

    def test_summary_records_both_socat_versions(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "summary.txt"
            bench.write_summary(
                {
                    "meta": {
                        "go_socat_version": "socat version 1.0.2-dev",
                        "classic_socat_version": "socat version 1.8.1.3",
                    },
                    "cases": [],
                },
                path,
            )
            summary = path.read_text(encoding="utf-8")
            self.assertIn("go_socat_version=socat version 1.0.2-dev", summary)
            self.assertIn("classic_socat_version=socat version 1.8.1.3", summary)


class RSSSamplerTest(unittest.TestCase):
    def test_unavailable_rss_is_reported_as_na(self) -> None:
        with mock.patch.object(bench, "rss_available", return_value=False):
            sampler = bench.RSSSampler([123])
            sampler.start()
            self.assertIsNone(sampler.stop())

        summary = bench.summarize_stream(
            [
                {
                    "status": "ok",
                    "mib_s": 100.0,
                    "elapsed_s": 1.0,
                    "peak_rss_kib": None,
                }
            ]
        )
        self.assertIsNone(summary["peak_rss_kib"])
        self.assertEqual(bench.rss_text(summary["peak_rss_kib"]), "n/a")
        self.assertEqual(bench.rss_value(summary["peak_rss_kib"]), "n/a")


class StorageTest(unittest.TestCase):
    def test_run_session_removes_stale_runs_and_current_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            workdir = Path(tempdir) / "work"
            workdir.mkdir()
            unrelated = workdir / "storage"
            unrelated.mkdir()
            (unrelated / "keep").write_text("mine", encoding="utf-8")
            root = Path(tempdir) / "owned"
            stale = root / "run-stale"
            stale.mkdir(parents=True)
            (stale / "payload").write_bytes(b"old")

            with mock.patch.object(bench, "benchmark_storage_root", return_value=root):
                with bench.run_session(workdir, 0) as run_dir:
                    self.assertEqual(run_dir.parent, root)
                    self.assertTrue(run_dir.name.startswith("run-"))
                    self.assertFalse(stale.exists())
                    (run_dir / "payload").write_bytes(b"new")
                    marker = run_dir

            self.assertFalse(marker.exists())
            self.assertTrue((root / ".lock").is_file())
            self.assertEqual((unrelated / "keep").read_text(encoding="utf-8"), "mine")

    def test_run_session_rejects_symlink_root(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            real = Path(tempdir) / "real"
            real.mkdir()
            link = Path(tempdir) / "link"
            link.symlink_to(real)
            with mock.patch.object(bench, "benchmark_storage_root", return_value=link):
                with self.assertRaisesRegex(SystemExit, "must not be a symlink"):
                    with bench.run_session(Path(tempdir), 0):
                        pass

    def test_run_session_checks_free_space_under_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            workdir = Path(tempdir) / "work"
            root = Path(tempdir) / "owned"
            with mock.patch.object(bench, "benchmark_storage_root", return_value=root):
                with mock.patch.object(bench.shutil, "disk_usage", return_value=mock.Mock(free=0)):
                    with self.assertRaisesRegex(SystemExit, "reduce SOCAT_BENCH_SIZE"):
                        with bench.run_session(workdir, 256):
                            pass
            self.assertTrue((root / ".lock").is_file())
            self.assertFalse(any(root.glob("run-*")))

    def test_storage_root_falls_back_when_shm_cannot_exec(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            workdir = Path(tempdir)
            with mock.patch.object(bench, "linux_shm_root", return_value=None):
                self.assertEqual(bench.benchmark_storage_root(workdir), workdir / "storage")
            self.assertTrue(bench.dir_allows_exec(workdir))

    def test_prepare_payload_writes_fresh_files(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            run_dir = Path(tempdir)
            size = 256
            buffer = 64

            def fake_generate(_client: Path, dest: Path, n: int) -> None:
                dest.write_bytes(bytes(range(n)))

            with mock.patch.object(bench, "generate_aes_ctr", side_effect=fake_generate) as gen:
                with mock.patch.object(bench.shutil, "disk_usage", return_value=mock.Mock(free=10**12)):
                    payload, note, framed = bench.prepare_payload(
                        run_dir, size, buffer, ("udp",), Path("benchclient")
                    )

            self.assertEqual(gen.call_count, 1)
            self.assertEqual(note, "aes-128-ctr (incompressible)")
            self.assertEqual(payload, run_dir / "payload")
            self.assertEqual(framed, run_dir / "payload.dgram")
            self.assertEqual(payload.stat().st_size, size)
            self.assertGreater(framed.stat().st_size, size)

    def test_prepare_payload_fails_before_filling_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            run_dir = Path(tempdir)
            usage = mock.Mock(free=0)
            with mock.patch.object(bench.shutil, "disk_usage", return_value=usage):
                with self.assertRaisesRegex(SystemExit, "reduce SOCAT_BENCH_SIZE"):
                    bench.require_free_space(run_dir, 256)


class DatagramFrameTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.buffer = 64
        self.payload_per_frame = self.buffer - bench.DATAGRAM_HEADER.size

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def framed_payload(self, frames: int = 4) -> tuple[Path, int, int, int]:
        size = self.payload_per_frame * frames
        payload = self.root / "payload"
        payload.write_bytes(bytes((i % 251) + 1 for i in range(size)))
        framed = self.root / "framed"
        frame_count, wire_size = bench.write_datagram_payload(payload, framed, size, self.buffer)
        return framed, frame_count, wire_size, size

    def chunks(self, framed: Path) -> list[bytes]:
        data = framed.read_bytes()
        return [data[i : i + self.buffer] for i in range(0, len(data), self.buffer)]

    def test_complete_payload_is_valid_and_lossless(self) -> None:
        framed, frame_count, wire_size, size = self.framed_payload()
        metrics = bench.analyze_datagram_sink(framed, size, self.buffer)

        self.assertEqual(metrics["expected_datagrams"], frame_count)
        self.assertEqual(metrics["unique_datagrams"], frame_count)
        self.assertEqual(metrics["received_payload_bytes"], size)
        self.assertEqual(metrics["received_wire_bytes"], wire_size)
        self.assertEqual(metrics["missing_datagrams"], 0)
        self.assertEqual(metrics["loss_pct"], 0.0)
        self.assertEqual(metrics["duplicate_datagrams"], 0)
        self.assertEqual(metrics["reordered_datagrams"], 0)
        self.assertEqual(metrics["corrupt_datagrams"], 0)

    def test_loss_duplicates_and_reordering_are_counted(self) -> None:
        framed, _, _, size = self.framed_payload()
        frames = self.chunks(framed)
        sink = self.root / "sink"
        sink.write_bytes(frames[2] + frames[0] + frames[2])

        metrics = bench.analyze_datagram_sink(sink, size, self.buffer)

        self.assertEqual(metrics["received_datagrams"], 3)
        self.assertEqual(metrics["unique_datagrams"], 2)
        self.assertEqual(metrics["missing_datagrams"], 2)
        self.assertEqual(metrics["duplicate_datagrams"], 1)
        self.assertEqual(metrics["reordered_datagrams"], 1)
        self.assertEqual(metrics["loss_pct"], 50.0)

    def test_partial_final_frame_preserves_logical_payload_size(self) -> None:
        size = self.payload_per_frame * 2 + 7
        payload = self.root / "payload"
        payload.write_bytes(bytes((i % 251) + 1 for i in range(size)))
        framed = self.root / "framed"
        frame_count, _ = bench.write_datagram_payload(payload, framed, size, self.buffer)

        metrics = bench.analyze_datagram_sink(framed, size, self.buffer)

        self.assertEqual(frame_count, 3)
        self.assertEqual(metrics["unique_datagrams"], 3)
        self.assertEqual(metrics["received_payload_bytes"], size)
        self.assertEqual(metrics["corrupt_datagrams"], 0)

    def test_partial_frames_with_the_same_frame_count_differ(self) -> None:
        payload = self.root / "payload"
        payload.write_bytes(bytes(range(self.payload_per_frame)))
        first_size = self.payload_per_frame - 2
        second_size = self.payload_per_frame - 1
        first = self.root / "first"
        second = self.root / "second"

        bench.write_datagram_payload(payload, first, first_size, self.buffer)
        bench.write_datagram_payload(payload, second, second_size, self.buffer)

        self.assertNotEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(
            bench.analyze_datagram_sink(first, first_size, self.buffer)["corrupt_datagrams"], 0
        )
        self.assertEqual(
            bench.analyze_datagram_sink(second, second_size, self.buffer)["corrupt_datagrams"], 0
        )

    def test_corruption_and_partial_frames_are_rejected(self) -> None:
        framed, _, _, size = self.framed_payload(frames=1)
        frame = bytearray(framed.read_bytes())
        frame[bench.DATAGRAM_HEADER.size] ^= 0xFF
        sink = self.root / "sink"
        sink.write_bytes(frame + b"partial")

        metrics = bench.analyze_datagram_sink(sink, size, self.buffer)

        self.assertEqual(metrics["unique_datagrams"], 0)
        self.assertEqual(metrics["missing_datagrams"], 1)
        self.assertEqual(metrics["corrupt_datagrams"], 2)
        self.assertEqual(metrics["trailing_bytes"], len(b"partial"))

    def test_invalid_buffer_sizes_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            bench.datagram_frame_count(1, bench.DATAGRAM_HEADER.size)
        with self.assertRaises(ValueError):
            bench.datagram_frame_count(1, bench.DATAGRAM_MAX_SIZE + 1)


class DatagramAddrTest(unittest.TestCase):
    def test_udp_uses_recv_sendto(self) -> None:
        certs = {"crt": Path("c"), "key": Path("k"), "ca": Path("a")}
        udp_listen, udp_connect = bench.stream_addrs("udp", 9, Path("sock"), certs)

        self.assertTrue(udp_listen.startswith("UDP4-RECV:9,"))
        self.assertTrue(udp_connect.startswith("UDP4-SENDTO:127.0.0.1:9,"))
        self.assertEqual(bench.DATAGRAM_CASES, {"udp"})


class DatagramSummaryTest(unittest.TestCase):
    def test_summary_keeps_rate_and_delivery_metrics(self) -> None:
        runs = []
        for send, receive, loss in ((100.0, 80.0, 2.0), (120.0, 90.0, 4.0)):
            runs.append(
                {
                    "status": "ok",
                    "send_mib_s": send,
                    "receive_mib_s": receive,
                    "loss_pct": loss,
                    "duplicate_datagrams": 1,
                    "reordered_datagrams": 2,
                    "corrupt_datagrams": 0,
                    "expected_datagrams": 10,
                    "peak_rss_kib": 100,
                }
            )

        summary = bench.summarize_datagram(runs)

        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["kind"], "datagram")
        self.assertEqual(summary["send_mib_s"]["median"], 110.0)
        self.assertEqual(summary["receive_mib_s"]["median"], 85.0)
        self.assertEqual(summary["loss_pct"]["median"], 3.0)
        self.assertEqual(summary["duplicate_datagrams"]["total"], 2)
        self.assertEqual(summary["reordered_datagrams"]["total"], 4)


class StreamSummaryTest(unittest.TestCase):
    def test_websocket_addresses_are_go_only_stream_cases(self) -> None:
        certs = {"crt": Path("server.crt"), "key": Path("server.key"), "ca": Path("ca.pem")}

        ws_listen, ws_connect = bench.stream_addrs("ws", 9, Path("sock"), certs)
        wss_listen, wss_connect = bench.stream_addrs("wss", 10, Path("sock"), certs)

        self.assertEqual(ws_listen, "WS-LISTEN:9,reuseaddr,bind=127.0.0.1")
        self.assertEqual(ws_connect, "WS:127.0.0.1:9")
        self.assertIn("cert=server.crt,key=server.key", wss_listen)
        self.assertIn("verify=1,cafile=ca.pem,commonname=localhost", wss_connect)
        self.assertTrue({"ws", "wss"} <= bench.STREAM_CASES)
        self.assertTrue({"ws", "wss"} <= set(bench.GO_ONLY))
        self.assertEqual(bench.GO_ONLY["ws"], "WebSocket")
        self.assertEqual(bench.GO_ONLY["wss"], "WebSocket")
        self.assertEqual(bench.GO_ONLY["quic"], "QUIC")

    def test_partial_failure_keeps_failure_detail(self) -> None:
        summary = bench.summarize_stream(
            [
                {"status": "fail", "detail": "sink was short"},
                {
                    "status": "ok",
                    "mib_s": 100.0,
                    "elapsed_s": 1.0,
                    "peak_rss_kib": 100,
                },
            ]
        )

        self.assertEqual(summary["status"], "fail")
        self.assertEqual(summary["detail"], "sink was short")


if __name__ == "__main__":
    unittest.main()
