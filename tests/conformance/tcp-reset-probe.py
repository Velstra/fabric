#!/usr/bin/env python3
"""Disposable real-socket TCP reset oracle; no Fabric parser/state is imported.

The VM driver owns namespaces, routes, capture and the ready/release barrier.
Raw injection needs CAP_NET_RAW. Never run against a production interface.
"""

import argparse
import hashlib
import json
from pathlib import Path
import select
import socket
import struct
import threading
import time
import unittest
from unittest import mock

PORT = 18198
CASES = ("foreign-tuple", "wrong-sequence", "valid-reset", "in-window-nonexact", "bad-checksum")


def challenge_ack_counter(text):
    lines = text.splitlines()
    for index, line in enumerate(lines):
        names = line.split()
        if not names or names[0] != "TcpExt:" or "TCPChallengeACK" not in names:
            continue
        if index + 1 >= len(lines):
            raise ValueError("missing TcpExt counter values")
        values = lines[index + 1].split()
        if len(values) != len(names) or values[0] != names[0]:
            raise ValueError("invalid TcpExt counter shape")
        value = values[names.index("TCPChallengeACK")]
        if not value.isascii() or not value.isdecimal():
            raise ValueError("invalid challenge ACK counter")
        return int(value)
    raise ValueError("missing TCPChallengeACK counter")


def checksum(data):
    data = bytes(data)
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def tcp_frame(frame):
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        raise ValueError("short IPv4 header")
    ihl = (ip[0] & 15) * 4
    total = struct.unpack_from("!H", ip, 2)[0]
    if ihl < 20 or ihl > 60 or total < ihl or len(ip) < total:
        raise ValueError("invalid IPv4 bounds")
    if ip[9] != 6 or struct.unpack_from("!H", ip, 6)[0] & 0x3fff:
        return None
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        raise ValueError("short TCP header")
    offset = (tcp[12] >> 4) * 4
    if offset < 20 or offset > len(tcp):
        raise ValueError("invalid TCP bounds")
    source, target = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    sport, dport, seq, ack = struct.unpack_from("!HHII", tcp)
    pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
    return {"source": source, "destination": target,
            "source_port": sport, "destination_port": dport,
            "seq": seq, "ack": ack, "flags": tcp[13],
            "payload": tcp[offset:], "id": struct.unpack_from("!H", ip, 4)[0],
            "ip_checksum_valid": checksum(ip[:ihl]) == 0,
            "tcp_checksum_valid": checksum(pseudo + tcp) == 0}


def reset_frame(ready, case, destination_mac, source_mac):
    if case not in CASES:
        raise ValueError("unknown reset case")
    displacement = {"wrong-sequence": 0x40000000, "in-window-nonexact": 1}.get(case, 0)
    seq = (ready["next_server_seq"] + displacement) & 0xffffffff
    dport = ready["client_port"] + (1 if case == "foreign-tuple" else 0)
    source = socket.inet_aton(ready["server"])
    target = socket.inet_aton(ready["client"])
    tcp = bytearray(struct.pack("!HHIIBBHHH", PORT, dport, seq,
        ready["next_client_seq"], 0x50, 0x14, 4096, 0, 0))
    pseudo = source + target + struct.pack("!BBH", 0, 6, len(tcp))
    struct.pack_into("!H", tcp, 16, checksum(pseudo + tcp))
    if case == "bad-checksum":
        # Exact accepted reset tuple/sequence, differing ONLY in one checksum
        # bit. Raw Ethernet injection must not request NIC checksum completion.
        tcp[16] ^= 1
    ip = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40,
        ready["ident"], 0, 64, 6, 0, source, target))
    struct.pack_into("!H", ip, 10, checksum(ip))
    # Supply the Ethernet minimum (without FCS) ourselves. A 54-byte raw send
    # otherwise lets the NIC add six padding bytes, so an exact full-wire hash
    # would compare different frames despite identical IPv4/TCP datagrams.
    return (destination_mac + source_mac + b"\x08\x00" + ip + tcp).ljust(60, b"\0")


def echo_connection(connection):
    with connection:
        connection.settimeout(20)
        try:
            while data := connection.recv(4096):
                connection.sendall(data)
        except OSError:
            pass


def server(args):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.bind, PORT))
        listener.listen(8)
        while True:
            connection, _ = listener.accept()
            threading.Thread(target=echo_connection, args=(connection,), daemon=True).start()


def receive_exact(connection, expected):
    received = b""
    while len(received) < len(expected):
        data = connection.recv(len(expected) - len(received))
        if not data:
            raise EOFError("peer closed before echo completed")
        received += data
    if received != expected:
        raise ValueError("echo payload differs")
    return hashlib.sha256(received).hexdigest()


def next_sequences(capture, client, client_port, server_address, baseline):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        ready, _, _ = select.select([capture], [], [], max(0, deadline - time.monotonic()))
        if not ready:
            break
        packet = tcp_frame(capture.recv(65535))
        if packet is None:
            continue
        if ((packet["source"], packet["source_port"], packet["destination"], packet["destination_port"])
                == (server_address, PORT, client, client_port) and packet["payload"] == baseline
                and packet["flags"] & 0x10 and not packet["flags"] & 0x07):
            # This real echo acknowledges every byte sent by the client and
            # supplies the server's next sequence directly. ETH_P_IP taps need
            # not see an outgoing client pure ACK; requiring one would make a
            # completed native echo fail for capture setup, not TCP behavior.
            return packet["ack"], (packet["seq"] + len(baseline)) & 0xffffffff
    raise TimeoutError("actual complete echo/ACK sequence observation missing")


def session(args):
    directory = Path(args.directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    baseline = b"reset-window-native-baseline\n"
    after = b"same-live-socket-after-injected-reset\n"
    report = {"schema": 1, "case": args.case, "baseline_ok": False,
              "post_echo_ok": False, "socket_error_before_echo": None,
              "endpoint_exception": None, "received_injected_reset": None}
    with (socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as capture,
          socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection):
        capture.bind((args.interface, 0))
        capture.setblocking(False)
        connection.settimeout(2)
        connection.bind((args.bind, args.source_port))
        connection.connect((args.target, PORT))
        connection.sendall(baseline)
        report["baseline_sha256"] = receive_exact(connection, baseline)
        report["baseline_ok"] = True
        client_seq, server_seq = next_sequences(capture, args.bind, args.source_port, args.target, baseline)
        ready = {"client": args.bind, "server": args.target, "client_port": args.source_port,
                 "next_client_seq": client_seq, "next_server_seq": server_seq, "ident": args.ident}
        report["challenge_ack_before"] = challenge_ack_counter(Path("/proc/net/netstat").read_text())
        (directory / "ready.json").write_text(json.dumps(ready) + "\n")
        deadline = time.monotonic() + 15
        while not (directory / "release").exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("driver did not release observed session")
            time.sleep(0.01)
        if (directory / "release").read_text() != "observe\n":
            raise ValueError("unknown driver action")
        report["challenge_ack_after"] = challenge_ack_counter(Path("/proc/net/netstat").read_text())
        report["socket_error_before_echo"] = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        try:
            connection.sendall(after)
            report["post_sha256"] = receive_exact(connection, after)
            report["post_echo_ok"] = True
        except (OSError, EOFError, ValueError) as error:
            report["endpoint_exception"] = type(error).__name__
            report["endpoint_errno"] = getattr(error, "errno", None)
        for _ in range(512):
            try:
                packet = tcp_frame(capture.recv(65535))
            except BlockingIOError:
                break
            if packet is not None and packet["id"] == args.ident and packet["flags"] & 4:
                report["received_injected_reset"] = {key: value for key, value in packet.items() if key != "payload"}
        report["ready"] = ready
    report["passed"] = (report["baseline_ok"] and
        ((not report["post_echo_ok"] and report["socket_error_before_echo"] == 104)
         if args.case == "valid-reset" else
         (report["post_echo_ok"] and report["socket_error_before_echo"] == 0)))
    if args.case == "in-window-nonexact":
        # Actual native-stack response establishes that this is an in-window
        # nonexact reset, rather than relying on a guessed advertised window.
        report["passed"] = (report["passed"] and report["received_injected_reset"] is not None
            and report["challenge_ack_after"] > report["challenge_ack_before"])
    (directory / "report.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(not report["passed"])


def inject(args):
    ready = json.loads(Path(args.ready).read_text())
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sender:
        sender.bind((args.interface, 0))
        destination = bytes.fromhex(args.destination_mac.replace(":", ""))
        frame = reset_frame(ready, args.case, destination, sender.getsockname()[4])
        parsed = tcp_frame(frame)
        assert parsed["ip_checksum_valid"]
        assert parsed["tcp_checksum_valid"] is (args.case != "bad-checksum")
        assert sender.send(frame) == len(frame)
    print(json.dumps({"schema": 1, "case": args.case, "frame_sha256": hashlib.sha256(frame).hexdigest(),
        "destination_mac": args.destination_mac, "packet": {key: value for key, value in parsed.items() if key != "payload"}}, sort_keys=True))


class PacketOracles(unittest.TestCase):
    READY = {"client": "198.19.20.50", "server": "198.19.10.254", "client_port": 42000,
             "next_client_seq": 0xfffffffc, "next_server_seq": 0xf0000000, "ident": 0x7200}

    def frame(self, case="wrong-sequence"):
        return reset_frame(self.READY, case, bytes.fromhex("020000000001"), bytes.fromhex("020000000002"))

    def test_independent_rfc1071_vector_and_odd_input(self):
        self.assertEqual(checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220d)
        self.assertEqual(checksum(b"123"), checksum(b"123\0"))

    def test_wrong_sequence_wraps_without_changing_tuple_or_ack(self):
        packet = tcp_frame(self.frame())
        self.assertEqual((packet["seq"], packet["ack"]), (0x30000000, 0xfffffffc))
        self.assertEqual((packet["source_port"], packet["destination_port"]), (PORT, 42000))
        self.assertTrue(packet["ip_checksum_valid"] and packet["tcp_checksum_valid"])
        self.assertEqual(packet["flags"], 0x14)

    def test_in_window_control_advances_one_and_wraps(self):
        packet = tcp_frame(self.frame("in-window-nonexact"))
        self.assertEqual(packet["seq"], self.READY["next_server_seq"] + 1)
        self.assertEqual(packet["ack"], self.READY["next_client_seq"])
        ready = self.READY | {"next_server_seq": 0xffffffff}
        wrapped = tcp_frame(reset_frame(ready, "in-window-nonexact", bytes(6), bytes(6)))
        self.assertEqual(wrapped["seq"], 0)
        self.assertTrue(wrapped["ip_checksum_valid"] and wrapped["tcp_checksum_valid"])

    def test_native_challenge_counter_requires_matching_header_and_values(self):
        self.assertEqual(challenge_ack_counter("TcpExt: Other TCPChallengeACK\nTcpExt: 8 12\n"), 12)
        for text in ("", "TcpExt: Other\nTcpExt: 1\n", "TcpExt: TCPChallengeACK\n",
                     "TcpExt: TCPChallengeACK\nIpExt: 1\n", "TcpExt: TCPChallengeACK\nTcpExt: -1\n",
                     "TcpExt: TCPChallengeACK Other\nTcpExt: 1\n"):
            with self.assertRaises(ValueError):
                challenge_ack_counter(text)

    def test_ethernet_minimum_padding_is_explicit_and_outside_ip_length(self):
        frame = self.frame()
        self.assertEqual(len(frame), 60)
        self.assertEqual(frame[54:], bytes(6))
        self.assertEqual(struct.unpack_from("!H", frame, 16)[0], 40)
        self.assertTrue(tcp_frame(frame)["tcp_checksum_valid"])

    def test_valid_and_foreign_controls_change_only_intended_fields(self):
        valid = tcp_frame(self.frame("valid-reset"))
        foreign = tcp_frame(self.frame("foreign-tuple"))
        self.assertEqual(valid["seq"], self.READY["next_server_seq"])
        self.assertEqual(foreign["seq"], valid["seq"])
        self.assertEqual(foreign["destination_port"], valid["destination_port"] + 1)
        for packet in (valid, foreign):
            self.assertTrue(packet["ip_checksum_valid"] and packet["tcp_checksum_valid"])

    def test_corrupt_tcp_checksum_is_not_reported_valid(self):
        frame = bytearray(self.frame())
        frame[14 + 20 + 16] ^= 1
        self.assertFalse(tcp_frame(frame)["tcp_checksum_valid"])

    def test_bad_checksum_control_changes_only_one_checksum_bit(self):
        valid = self.frame("valid-reset")
        corrupt = self.frame("bad-checksum")
        self.assertEqual([i for i, pair in enumerate(zip(valid, corrupt)) if pair[0] != pair[1]], [50])
        self.assertEqual(valid[50] ^ corrupt[50], 1)
        packet = tcp_frame(corrupt)
        self.assertTrue(packet["ip_checksum_valid"])
        self.assertFalse(packet["tcp_checksum_valid"])
        self.assertEqual(packet["seq"], self.READY["next_server_seq"])
        self.assertEqual(packet["ack"], self.READY["next_client_seq"])
        self.assertEqual(packet["flags"], 0x14)

    def test_invalid_lengths_and_offsets_are_rejected(self):
        frame = self.frame()
        for length in (14, 30, 40, 53):
            with self.assertRaises(ValueError):
                tcp_frame(frame[:length])
        frame = bytearray(frame)
        frame[14 + 20 + 12] = 0xf0
        with self.assertRaises(ValueError):
            tcp_frame(frame)

    def test_fragments_and_other_ethertypes_do_not_supply_tcp_sequences(self):
        frame = bytearray(self.frame())
        frame[14 + 6] = 0x20
        self.assertIsNone(tcp_frame(frame))
        frame[12:14] = b"\x86\xdd"
        self.assertIsNone(tcp_frame(frame))

    def test_unknown_case_never_injects_a_default_packet(self):
        with self.assertRaises(ValueError):
            self.frame("not-a-test")

    def test_completed_incoming_echo_supplies_both_sequences_without_outgoing_tap(self):
        payload = b"real echoed bytes"
        frame = bytearray(self.frame("valid-reset")[:54])
        frame[47] = 0x18
        frame.extend(payload)
        struct.pack_into("!H", frame, 16, 40 + len(payload))
        capture = mock.Mock()
        capture.recv.return_value = bytes(frame)
        with mock.patch("select.select", return_value=([capture], [], [])):
            sequences = next_sequences(capture, self.READY["client"], self.READY["client_port"],
                self.READY["server"], payload)
        self.assertEqual(sequences, (self.READY["next_client_seq"], self.READY["next_server_seq"] + len(payload)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("selftest")
    listener = commands.add_parser("server")
    listener.add_argument("--bind", required=True)
    client = commands.add_parser("session")
    for name in ("interface", "bind", "target", "directory"):
        client.add_argument("--" + name, required=True)
    client.add_argument("--case", choices=CASES, required=True)
    client.add_argument("--source-port", type=int, required=True)
    client.add_argument("--ident", type=int, required=True)
    sender = commands.add_parser("inject")
    for name in ("interface", "ready", "destination-mac"):
        sender.add_argument("--" + name, required=True)
    sender.add_argument("--case", choices=CASES, required=True)
    args = parser.parse_args()
    if args.command == "selftest":
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(PacketOracles)
        raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
    {"server": server, "session": session, "inject": inject}[args.command](args)


if __name__ == "__main__":
    main()
