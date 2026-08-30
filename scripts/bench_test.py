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
        framed, frame_count, wire_size = bench.ensure_datagram_payload(payload, size, self.buffer)
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
        framed, frame_count, _ = bench.ensure_datagram_payload(payload, size, self.buffer)

        metrics = bench.analyze_datagram_sink(framed, size, self.buffer)

        self.assertEqual(frame_count, 3)
        self.assertEqual(metrics["unique_datagrams"], 3)
        self.assertEqual(metrics["received_payload_bytes"], size)
        self.assertEqual(metrics["corrupt_datagrams"], 0)

    def test_cache_distinguishes_sizes_with_the_same_frame_count(self) -> None:
        payload = self.root / "payload"
        payload.write_bytes(bytes(range(self.payload_per_frame)))
        first_size = self.payload_per_frame - 2
        second_size = self.payload_per_frame - 1

        first, _, _ = bench.ensure_datagram_payload(payload, first_size, self.buffer)
        second, _, _ = bench.ensure_datagram_payload(payload, second_size, self.buffer)

        self.assertNotEqual(first, second)
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
