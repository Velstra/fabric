#!/usr/bin/env python3
"""Independent Linux wire oracle for RELATED ICMPv4/NAT (stdlib only).

Dedicated lab, root/CAP_NET_RAW only. No Fabric parser/checksum is imported.
Run `peer --interface eth1 --bind ADDRESS` at the remote endpoint, then
`client --interface eth1 --bind ADDRESS --target ADDRESS` at the initiator.
Both endpoints must be routed through the DUT; target UDP/18199 must reach peer.
Use the same commands/topology with nftables as an independent reference.
This does not configure a firewall or certify unexecuted protocol/HA variants.
"""

import argparse
import errno
import json
from pathlib import Path
import select
import socket
import struct
import time
import unittest
from unittest import mock

MARKER = b"velstra-icmp-related-v1:"
PORT = 18199
ETH_IP = 0x0800
# Linux UAPI: include/uapi/linux/in.h and errqueue.h. Python3.13 does not
# expose IP_RECVERR on every build, so use its documented stable Linux value.
IP_RECVERR = 11
SO_EE_ORIGIN_ICMP = 2
EXTENDED_ERROR = struct.Struct("=IBBBBII")
VALID = (
    "port-min", "time-min", "parameter", "pmtu", "full", "options",
    "zero-udp", "odd-quote",
)
# These are not assertions of RFC validity. Linux conntrack forwards them as
# RELATED, and the two original discrepancies also reach the real UDP socket.
# Preserve malformed quoted checksum residuals instead of repairing the quote.
LINUX_COMPAT = (
    "bad-quote-checksum", "bad-code", "unassigned-unreachable-code",
    "unassigned-parameter-code", "unassigned-time-code",
)
FORWARDED = VALID + LINUX_COMPAT
INVALID = (
    "bad-outer-checksum", "bad-icmp-checksum", "bad-envelope-match",
    "unmatched-port", "unmatched-destination", "truncated", "nonfirst-fragment",
    "error-about-error",
)
HELD = ("missing-physical-state", "wrong-ingress", "expired-state")


def checksum(data):
    """RFC1071 full one's-complement sum, independent of incremental NAT code."""
    if len(data) & 1:
        # Padding is part of checksum arithmetic, not transmitted data. `+=`
        # mutates bytearray callers and silently turns a 27-byte short quote
        # into a valid 28-byte quote before the outer IPv4 length is built.
        data = data + b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def corrupt_quote_checksum(quote):
    """Add the same one's-complement error to every lane's quoted checksum.

    XOR of the high byte changes the sum by +256 OR -256 depending on the
    original checksum bit. Different NAT addresses/IP IDs would then generate
    different malformed inputs. End-around-carry addition always leaves the
    independently observable RFC1071 residual 0xfeff, including checksum zero
    and wraparound. It deliberately does not repair the quoted IPv4 checksum.
    """
    value = struct.unpack_from("!H", quote, 10)[0] + 0x0100
    struct.pack_into("!H", quote, 10, (value & 65535) + (value >> 16))


def ip_packet(source, destination, protocol, payload, ident, options=b"", fragment=0):
    assert len(options) % 4 == 0 and len(options) <= 40
    header = bytearray(struct.pack(
        "!BBHHHBBH4s4s", 0x45 + len(options) // 4, 0, 20 + len(options) + len(payload),
        ident, fragment, 64, protocol, 0, socket.inet_aton(source), socket.inet_aton(destination),
    ) + options)
    struct.pack_into("!H", header, 10, checksum(header))
    return bytes(header) + payload


def ipv4(data):
    if len(data) < 20 or data[0] >> 4 != 4:
        raise ValueError("not a complete IPv4 header")
    ihl = (data[0] & 15) * 4
    total = struct.unpack_from("!H", data, 2)[0]
    if ihl < 20 or ihl > 60 or len(data) < ihl or total < ihl:
        raise ValueError("invalid IPv4 bounds")
    return {
        "ihl": ihl, "total": total, "proto": data[9],
        "source": socket.inet_ntoa(data[12:16]), "destination": socket.inet_ntoa(data[16:20]),
        "id": struct.unpack_from("!H", data, 4)[0],
        "fragment": struct.unpack_from("!H", data, 6)[0],
    }


def udp_checksum(source, destination, udp):
    pseudo = socket.inet_aton(source) + socket.inet_aton(destination) + struct.pack("!BBH", 0, 17, len(udp))
    return checksum(pseudo + udp)


def request(frame):
    if len(frame) < 14 or struct.unpack_from("!H", frame, 12)[0] != ETH_IP:
        return None
    packet = frame[14:]
    ip = ipv4(packet)
    if ip["proto"] != 17 or ip["fragment"] & 0x1fff or len(packet) < ip["total"]:
        return None
    udp = packet[ip["ihl"]:ip["total"]]
    if len(udp) < 8 or struct.unpack_from("!H", udp, 2)[0] != PORT or not udp[8:].startswith(MARKER):
        return None
    meta = json.loads(udp[8 + len(MARKER):].rstrip(b" "))
    return packet[:ip["total"]], ip, meta


def error_packet(packet, ip, case, source, ident):
    """Build real, checksummed error packets; selected cases corrupt one invariant."""
    udp = bytearray(packet[ip["ihl"]:])
    # RX offload metadata is not portable between VM NICs: calculate an actual
    # transport checksum before quoting, rather than trusting capture metadata.
    struct.pack_into("!H", udp, 6, 0)
    struct.pack_into("!H", udp, 6, udp_checksum(ip["source"], ip["destination"], udp) or 65535)
    if case == "zero-udp":
        struct.pack_into("!H", udp, 6, 0)
    if case in {"unmatched-port", "unrelated-non-nat"}:
        struct.pack_into("!H", udp, 0, (struct.unpack_from("!H", udp)[0] + 1) & 65535)
    destination = ip["destination"] if case != "unmatched-destination" else "203.0.113.241"
    quote = bytearray(ip_packet(
        ip["source"], destination, 1 if case == "error-about-error" else 17,
        bytes(udp), ip["id"], b"\1" * 4 if case == "options" else b"",
        fragment=1 if case == "nonfirst-fragment" else 0,
    ))
    ihl = (quote[0] & 15) * 4
    if case == "error-about-error":
        quote[ihl:ihl + 2] = bytes([3, 3])
    if case == "bad-envelope-match":
        quote[12:16] = socket.inet_aton("203.0.113.242")
        struct.pack_into("!H", quote, 10, 0)
        struct.pack_into("!H", quote, 10, checksum(quote[:ihl]))
    if case == "bad-quote-checksum":
        corrupt_quote_checksum(quote)
    count = len(quote) if case == "full" else ihl + (9 if case == "odd-quote" else 8)
    if case == "truncated":
        count = ihl + 7
    kind, code = (11, 0) if case == "time-min" else (12, 0) if case == "parameter" else (3, 4) if case == "pmtu" else (3, 3)
    if case in LINUX_COMPAT:
        kind, code = {
            "bad-quote-checksum": (3, 3), "bad-code": (11, 2),
            "unassigned-unreachable-code": (3, 16),
            "unassigned-parameter-code": (12, 3), "unassigned-time-code": (11, 255),
        }[case]
    error = bytearray(struct.pack("!BBHI", kind, code, 0, 1280 if case == "pmtu" else 0))
    error.extend(quote[:count])
    struct.pack_into("!H", error, 2, checksum(error))
    if case == "bad-icmp-checksum":
        error[2] ^= 1
    response = bytearray(ip_packet(source, ip["source"], 1, bytes(error), ident))
    if case == "bad-outer-checksum":
        response[10] ^= 1
    return bytes(response)


def peer(args):
    # Bind the UDP target so the peer kernel does not emit competing automatic
    # port-unreachables for every adversarial case.
    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink.bind((args.bind, PORT))
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_IP))
    capture.bind((args.interface, 0))
    while True:
        frame = capture.recv(65535)
        try:
            parsed = request(frame)
            if parsed is None:
                continue
            packet, ip, meta = parsed
            # Especially important for hairpin tests where client and backend
            # share a host: never answer its OUTGOING pre-NAT VIP request.
            if ip["destination"] != args.bind:
                continue
            case = meta["case"]
            if case not in FORWARDED + INVALID + HELD + ("unrelated-non-nat",):
                continue
            response = error_packet(packet, ip, case, args.error_source or args.bind, meta["ident"])
            if case in HELD:
                # Fixed case names only: network metadata cannot select a path.
                # The VM driver must prove readiness and successful injection;
                # silence from an unconfigured/expired hold is never a pass.
                if not args.control_directory:
                    continue
                directory = Path(args.control_directory) / case
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                if any((directory / name).exists() for name in ("ready", "release", "sent", "suppressed")):
                    continue
                (directory / "response.ip").write_bytes(response)
                (directory / "ready.tmp").write_text(json.dumps({
                    "source": ip["source"], "destination": ip["destination"],
                    "source_port": struct.unpack_from("!H", packet, ip["ihl"])[0],
                    "destination_port": PORT, "ident": meta["ident"],
                }))
                (directory / "ready.tmp").replace(directory / "ready")
                deadline = time.monotonic() + 10
                while not (directory / "release").exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not (directory / "release").exists():
                    (directory / "timed-out").touch()
                    continue
                action = (directory / "release").read_text().strip()
                if action == "suppress":
                    (directory / "suppressed").touch()
                    continue
                if action != "send":
                    continue
            # L2 reversal sends to the actual router MAC without ARP/address
            # assumptions. Raw L2 retains intentional bad checksums unchanged.
            capture.send(frame[6:12] + frame[:6] + struct.pack("!H", ETH_IP) + response)
            if case in HELD:
                (directory / "sent").touch()
        except (ValueError, KeyError, struct.error, json.JSONDecodeError):
            continue


def inspect_error(frame, ident):
    if len(frame) < 14 or struct.unpack_from("!H", frame, 12)[0] != ETH_IP:
        return None
    packet = frame[14:]
    outer = ipv4(packet)
    if outer["proto"] != 1 or outer["id"] != ident or len(packet) < outer["total"]:
        return None
    body = packet[outer["ihl"]:outer["total"]]
    if len(body) < 36:
        raise ValueError("truncated received error")
    quote = body[8:]
    inner = ipv4(quote)
    if len(quote) < inner["ihl"] + 8:
        raise ValueError("short received quote")
    udp = quote[inner["ihl"]:]
    result = {
        "type": body[0], "code": body[1], "mtu": struct.unpack_from("!H", body, 6)[0],
        "outer_source": outer["source"], "outer_destination": outer["destination"],
        "source": inner["source"], "destination": inner["destination"],
        "source_port": struct.unpack_from("!H", udp)[0], "destination_port": struct.unpack_from("!H", udp, 2)[0],
        "outer_checksum_valid": checksum(packet[:outer["ihl"]]) == 0,
        "icmp_checksum_valid": checksum(body) == 0,
        "quote_checksum_valid": checksum(quote[:inner["ihl"]]) == 0,
        "quote_checksum_residual": checksum(quote[:inner["ihl"]]),
        "udp_checksum_zero": struct.unpack_from("!H", udp, 6)[0] == 0,
        "quote_ihl": inner["ihl"], "quote_bytes": len(quote),
    }
    length = struct.unpack_from("!H", udp, 4)[0]
    if len(udp) >= length and length >= 8 and not result["udp_checksum_zero"]:
        result["udp_checksum_valid"] = udp_checksum(inner["source"], inner["destination"], udp[:length]) == 0
    return result


def inspect_error_queue(message, payload, target, port, offender=None):
    """Validate native sock_extended_err plus IPv4 offender, not raw delivery.

    A quoted IPv4 header is not re-parsed or RFC-validated here. The purpose is
    to observe what this connected endpoint's real kernel accepted, including
    the deliberately malformed code/checksum variants under investigation.
    """
    data, ancillary, flags, address = message
    if flags != socket.MSG_ERRQUEUE:
        raise ValueError("truncated or unexpected error-queue flags")
    if len(ancillary) != 1 or ancillary[0][:2] != (socket.IPPROTO_IP, IP_RECVERR):
        raise ValueError("missing, duplicate or unexpected IP_RECVERR ancillary")
    value = ancillary[0][2]
    if len(value) != EXTENDED_ERROR.size + 16:
        raise ValueError("invalid IPv4 error-queue ancillary length")
    error, origin, kind, code, pad, info, extra = EXTENDED_ERROR.unpack_from(value)
    if origin != SO_EE_ORIGIN_ICMP or not 1 <= error <= 4095 or pad or extra:
        raise ValueError("invalid native ICMP extended error")
    family = struct.unpack_from("=H", value, EXTENDED_ERROR.size)[0]
    offender_port = struct.unpack_from("!H", value, EXTENDED_ERROR.size + 2)[0]
    offender_address = socket.inet_ntoa(value[EXTENDED_ERROR.size + 4:EXTENDED_ERROR.size + 8])
    if family != socket.AF_INET or offender_port or any(value[EXTENDED_ERROR.size + 8:]):
        raise ValueError("invalid IPv4 error-queue offender")
    if (not isinstance(address, tuple) or len(address) != 2
            or address != (target, port) or not payload.startswith(data)):
        raise ValueError("error queue does not identify this connected probe")
    if offender is not None and offender_address != offender:
        raise ValueError("error queue identifies an unexpected ICMP sender")
    return {"errno": error, "origin": origin, "type": kind, "code": code,
            "info": info, "offender": offender_address,
            "destination": address[0], "destination_port": address[1],
            "quoted_payload_bytes": len(data)}


def receive_error_queue(connection, payload, target, port, offender, deadline):
    # AF_PACKET can observe the frame before the kernel runs the UDP error
    # handler. Wait only within this case's original receive deadline. A late
    # queue observation must not extend every invalid-packet timeout anew.
    # Python's per-socket timeout can poll before recvmsg even with
    # MSG_DONTWAIT. Make nonblocking mode explicit so the deadline owns waits.
    connection.setblocking(False)
    while True:
        try:
            message = connection.recvmsg(65535, socket.CMSG_SPACE(32),
                socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT)
            result = inspect_error_queue(message, payload, target, port, offender)
            try:
                connection.recvmsg(65535, socket.CMSG_SPACE(32),
                    socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT)
            except BlockingIOError:
                return result
            raise ValueError("multiple errors received for one probe")
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(0.01, remaining))


def client(args):
    profiles = {
        "related": [(case, True) for case in FORWARDED] + [(case, False) for case in INVALID] + [("port-min", True)],
        "explicit-allow": [("unrelated-non-nat", True)],
        "stateful-off": [("port-min", False)],
        "stateful-off-allow": [("unrelated-non-nat", True)],
        "explicit-deny": [("port-min", False)],
        "block-icmp": [("port-min", False)],
        **{case: [(case, False)] for case in HELD},
    }
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_IP))
    capture.bind((args.interface, 0))
    capture.setblocking(False)
    reports = []
    for number, (case, expected) in enumerate(profiles[args.profile]):
        ident = 0x7100 + number
        source_port = args.source_port + number * 2
        meta = json.dumps({"case": case, "ident": ident}, separators=(",", ":")).encode()
        payload = MARKER + meta
        if case == "pmtu":
            payload = payload.ljust(1400, b" ")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.bind((args.bind, source_port))
            connection.setsockopt(socket.IPPROTO_IP, 10, 2)  # Linux IP_PMTUDISC_DO
            # Required for soft errors such as time-exceeded: plain recv()
            # otherwise gives EAGAIN for valid AND invalid-code observations.
            connection.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
            connection.connect((args.target, PORT))
            connection.send(payload)
            end = time.monotonic() + args.timeout
            observed = None
            while time.monotonic() < end:
                ready, _, _ = select.select([capture], [], [], max(0, end - time.monotonic()))
                if not ready:
                    break
                frame = capture.recv(65535)
                try:
                    found = inspect_error(frame, ident)
                except ValueError as error:
                    found = {"malformed": str(error)}
                if found is not None:
                    observed = found
                    break
            passed = (observed is not None) == expected
            if expected and observed is not None:
                expected_port = source_port + (case == "unrelated-non-nat")
                passed = passed and all(observed.get(key) == value for key, value in {
                    "source": args.bind, "destination": args.target,
                    "source_port": expected_port, "destination_port": PORT,
                    "outer_destination": args.bind, "outer_checksum_valid": True,
                    "icmp_checksum_valid": True,
                    "quote_checksum_valid": case != "bad-quote-checksum",
                }.items())
                if args.expected_error_source:
                    passed = passed and observed.get("outer_source") == args.expected_error_source
                if case == "pmtu":
                    passed = passed and (observed.get("type"), observed.get("code"), observed.get("mtu")) == (3, 4, 1280)
                if case == "full":
                    passed = passed and observed.get("udp_checksum_valid") is True
                if case == "zero-udp":
                    passed = passed and observed.get("udp_checksum_zero") is True
                if case == "options":
                    passed = passed and observed.get("quote_ihl") == 24
            connection.setblocking(False)
            kernel_errno = None
            try:
                connection.recv(65535)
            except OSError as error:
                kernel_errno = error.errno
            if case == "port-min" and expected:
                passed = passed and kernel_errno == errno.ECONNREFUSED
            try:
                queued = receive_error_queue(connection, payload, args.target, PORT,
                    args.expected_error_source, end)
            except (ValueError, OSError) as error:
                queued = {"malformed": str(error)}
                passed = False
            # Retain the original raw-wire decision/comparator. This second
            # assertion adds endpoint acceptance, not an exception for a
            # malformed reference packet or a way to turn parity red to green.
            # Linux's routing/conntrack and endpoint contracts differ here:
            # icmp_unreach discards destination-unreachable codes >15 before
            # dispatching to UDP. Require raw forwarding AND no socket error,
            # not a fabricated application-acceptance claim for that control.
            needs_queue = expected and case in FORWARDED and case != "unassigned-unreachable-code"
            passed = passed and ((queued is not None) == needs_queue)
            if needs_queue and queued is not None:
                kind, code, expected_errno, info = (
                    (11, 0, errno.EHOSTUNREACH, 0) if case == "time-min" else
                    (11, 2, errno.EHOSTUNREACH, 0) if case == "bad-code" else
                    (11, 255, errno.EHOSTUNREACH, 0) if case == "unassigned-time-code" else
                    (12, 0, errno.EPROTO, 0) if case == "parameter" else
                    (12, 3, errno.EPROTO, 0) if case == "unassigned-parameter-code" else
                    (3, 4, errno.EMSGSIZE, 1280) if case == "pmtu" else
                    (3, 3, errno.ECONNREFUSED, 0)
                )
                passed = passed and all(queued.get(key) == value for key, value in
                    {"type": kind, "code": code, "errno": expected_errno, "info": info}.items())
            reports.append({"case": case, "expected_delivery": expected, "passed": bool(passed),
                "observed": observed, "kernel_errno": kernel_errno, "error_queue": queued})
    print(json.dumps({"schema": 1, "profile": args.profile, "results": reports}, sort_keys=True))
    raise SystemExit(not all(report["passed"] for report in reports))


class OfflineOracles(unittest.TestCase):
    @staticmethod
    def queued_message(kind=11, code=0, error=errno.EHOSTUNREACH):
        # Independent native UAPI packing, not the parser's Struct instance.
        value = struct.pack("=IBBBBII", error, 2, kind, code, 0, 0, 0)
        value += struct.pack("=H", socket.AF_INET) + bytes(2)
        value += socket.inet_aton("198.51.100.2") + bytes(8)
        return (b"", [(socket.IPPROTO_IP, 11, value)], socket.MSG_ERRQUEUE,
                ("198.51.100.2", PORT))

    def test_native_error_queue_records_valid_time_and_bad_code_without_rfc_assumptions(self):
        self.assertEqual(EXTENDED_ERROR.size, 16)
        for code in (0, 2):
            result = inspect_error_queue(self.queued_message(code=code), b"probe",
                "198.51.100.2", PORT, "198.51.100.2")
            self.assertEqual((result["origin"], result["type"], result["code"], result["errno"]),
                (SO_EE_ORIGIN_ICMP, 11, code, errno.EHOSTUNREACH))

    def test_error_queue_rejects_truncation_duplicates_missing_and_unknown_ancillary(self):
        message = self.queued_message()
        data, ancillary, flags, address = message
        value = ancillary[0][2]
        invalid = [
            (data, [], flags, address),
            (data, ancillary * 2, flags, address),
            (data, [(socket.SOL_SOCKET, 11, value)], flags, address),
            (data, [(socket.IPPROTO_IP, 12, value)], flags, address),
            (data, ancillary, 0, address),
            (data, ancillary, flags | socket.MSG_CTRUNC, address),
            (data, ancillary, flags | socket.MSG_TRUNC, address),
        ]
        invalid += [(data, [(socket.IPPROTO_IP, 11, wrong)], flags, address)
                    for wrong in (value[:16], value[:-1], value + b"\0")]
        for bad in invalid:
            with self.subTest(ancillary_bytes=[len(item[2]) for item in bad[1]], flags=bad[2]):
                with self.assertRaises(ValueError):
                    inspect_error_queue(bad, b"probe", "198.51.100.2", PORT)

    def test_error_queue_rejects_non_icmp_origin_bad_reserved_fields_and_offender(self):
        data, ancillary, flags, address = self.queued_message()
        base = ancillary[0][2]
        variants = []
        for offset in (4, 7, 12, 16, 18, 24):
            wrong = bytearray(base)
            wrong[offset] ^= 1
            variants.append(bytes(wrong))
        variants.append(bytes(4) + base[4:])  # errno0 is not an error
        for value in variants:
            with self.assertRaises(ValueError):
                inspect_error_queue((data, [(socket.IPPROTO_IP, 11, value)], flags, address),
                    b"probe", "198.51.100.2", PORT)

    def test_error_queue_must_identify_this_socket_payload_and_icmp_sender(self):
        data, ancillary, flags, address = self.queued_message()
        for bad in ((data, ancillary, flags, ("203.0.113.1", PORT)),
                    (data, ancillary, flags, (address[0], PORT + 1)),
                    (b"foreign probe", ancillary, flags, address)):
            with self.assertRaises(ValueError):
                inspect_error_queue(bad, b"probe", "198.51.100.2", PORT)
        with self.assertRaises(ValueError):
            inspect_error_queue(self.queued_message(), b"probe", "198.51.100.2", PORT, "203.0.113.1")

    def test_error_queue_waits_for_endpoint_handler_only_within_original_deadline(self):
        connection = mock.Mock()
        connection.recvmsg.side_effect = [BlockingIOError(), self.queued_message(), BlockingIOError()]
        with mock.patch("time.monotonic", return_value=1), mock.patch("time.sleep") as pause:
            result = receive_error_queue(connection, b"probe", "198.51.100.2", PORT,
                "198.51.100.2", 2)
        self.assertEqual(result["errno"], errno.EHOSTUNREACH)
        connection.setblocking.assert_called_once_with(False)
        pause.assert_called_once_with(0.01)
        connection.recvmsg.side_effect = BlockingIOError()
        with mock.patch("time.monotonic", return_value=2), mock.patch("time.sleep") as pause:
            self.assertIsNone(receive_error_queue(connection, b"probe", "198.51.100.2", PORT, None, 2))
        pause.assert_not_called()

    def test_multiple_endpoint_errors_cannot_be_silently_discarded(self):
        connection = mock.Mock()
        connection.recvmsg.return_value = self.queued_message()
        with self.assertRaisesRegex(ValueError, "multiple errors"):
            receive_error_queue(connection, b"probe", "198.51.100.2", PORT, None, time.monotonic() + 1)

    def test_real_loopback_closed_udp_error_is_accepted_after_normal_recv(self):
        payload = b"disposable-local-kernel-error-queue-control"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.bind(("127.0.0.1", 0))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserved:
                reserved.bind(("127.0.0.1", 0))
                target = reserved.getsockname()
                connection.connect(target)
            connection.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
            connection.send(payload)
            connection.settimeout(1)
            with self.assertRaises(ConnectionRefusedError):
                connection.recv(65535)
            result = receive_error_queue(connection, payload, target[0], target[1],
                "127.0.0.1", time.monotonic() + 1)
            self.assertIsNotNone(result)
            self.assertEqual((result["errno"], result["type"], result["code"]),
                (errno.ECONNREFUSED, 3, 3))
            self.assertEqual(result["quoted_payload_bytes"], len(payload))

    def test_real_bound_udp_target_does_not_fabricate_an_icmp_error_queue(self):
        with (socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection,
              socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target):
            target.bind(("127.0.0.1", 0))
            connection.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
            connection.connect(target.getsockname())
            connection.send(b"local no-error positive control")
            result = receive_error_queue(connection, b"local no-error positive control",
                target.getsockname()[0], target.getsockname()[1], None, time.monotonic() + 0.025)
            self.assertIsNone(result)

    def test_rfc1071_vector(self):
        self.assertEqual(checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)

    def test_odd_checksum_does_not_pad_the_transmitted_buffer(self):
        data = bytearray.fromhex("0001f203f4f5f6")
        before = bytes(data)
        self.assertEqual(checksum(data), checksum(before))
        self.assertEqual(bytes(data), before)

    def test_short_and_odd_quotes_keep_their_exact_wire_lengths(self):
        udp = struct.pack("!HHHH", 41000, PORT, 16, 0) + b"12345678"
        packet = ip_packet("192.0.2.9", "198.51.100.2", 17, udp, 123)
        ip = ipv4(packet)
        for case, quote_bytes in (("truncated", 27), ("odd-quote", 29)):
            response = error_packet(packet, ip, case, "198.51.100.2", 28928)
            outer = ipv4(response)
            self.assertEqual(len(response), 20 + 8 + quote_bytes, case)
            self.assertEqual(outer["total"], len(response), case)
            self.assertEqual(checksum(response[20:]), 0, case)
        with self.assertRaisesRegex(ValueError, "truncated received error"):
            short = error_packet(packet, ip, "truncated", "198.51.100.2", 28928)
            inspect_error(bytes(12) + struct.pack("!H", ETH_IP) + short, 28928)

    def test_packet_builder_and_nested_checksums(self):
        payload = MARKER + b'{"case":"full","ident":28928}'
        udp = struct.pack("!HHHH", 41000, PORT, len(payload) + 8, 0) + payload
        packet = ip_packet("192.0.2.9", "198.51.100.2", 17, udp, 123)
        ip = ipv4(packet)
        for case in FORWARDED:
            response = error_packet(packet, ip, case, "198.51.100.2", 28928)
            observed = inspect_error(bytes(12) + struct.pack("!H", ETH_IP) + response, 28928)
            self.assertTrue(observed["outer_checksum_valid"], case)
            self.assertTrue(observed["icmp_checksum_valid"], case)
            self.assertEqual(observed["quote_checksum_valid"], case != "bad-quote-checksum", case)
            if case == "full":
                self.assertTrue(observed["udp_checksum_valid"])
        for case in ("bad-outer-checksum", "bad-icmp-checksum", "bad-quote-checksum", "bad-code", "nonfirst-fragment"):
            response = error_packet(packet, ip, case, "198.51.100.2", 28928)
            outer = ipv4(response)
            body = response[outer["ihl"]:]
            if case == "bad-outer-checksum":
                self.assertNotEqual(checksum(response[:outer["ihl"]]), 0)
                self.assertEqual(checksum(body), 0)
            elif case == "bad-icmp-checksum":
                self.assertNotEqual(checksum(body), 0)
                self.assertEqual(checksum(response[:outer["ihl"]]), 0)
            elif case == "bad-quote-checksum":
                self.assertNotEqual(checksum(body[8:28]), 0)
            elif case == "bad-code":
                self.assertEqual(body[:2], bytes([11, 2]))
            else:
                self.assertEqual(struct.unpack_from("!H", body, 14)[0] & 0x1fff, 1)

    def test_opaque_codes_have_independent_exact_wire_identity_and_valid_envelopes(self):
        udp = struct.pack("!HHHH", 41000, PORT, 16, 0) + b"12345678"
        packet = ip_packet("192.0.2.9", "198.51.100.2", 17, udp, 123)
        for case, identity in (
            ("bad-code", (11, 2)), ("unassigned-unreachable-code", (3, 16)),
            ("unassigned-parameter-code", (12, 3)), ("unassigned-time-code", (11, 255)),
        ):
            with self.subTest(case=case):
                response = error_packet(packet, ipv4(packet), case, "198.51.100.2", 28928)
                self.assertEqual(tuple(response[20:22]), identity)
                self.assertEqual(checksum(response[:20]), 0)
                self.assertEqual(checksum(response[20:]), 0)
                self.assertEqual(checksum(response[28:48]), 0)

    def test_corrupt_quote_is_not_an_outer_checksum_failure(self):
        udp = struct.pack("!HHHH", 41000, PORT, 16, 0) + b"12345678"
        packet = ip_packet("192.0.2.9", "198.51.100.2", 17, udp, 123)
        response = error_packet(packet, ipv4(packet), "bad-quote-checksum", "198.51.100.2", 28928)
        self.assertEqual(checksum(response[:20]), 0)
        self.assertEqual(checksum(response[20:]), 0)
        self.assertEqual(checksum(response[28:48]), 0xfeff)
        observed = inspect_error(bytes(12) + struct.pack("!H", ETH_IP) + response, 28928)
        self.assertEqual(observed["quote_checksum_residual"], checksum(response[28:48]))
        self.assertIn("bad-quote-checksum", FORWARDED)
        self.assertIn("bad-icmp-checksum", INVALID)
        self.assertIn("bad-outer-checksum", INVALID)
        self.assertFalse(set(FORWARDED) & set(INVALID))

    def test_corruption_has_one_residual_for_every_checksum_word_including_zero_and_wrap(self):
        # Independent arithmetic oracle: modulo 65535 represents end-around
        # carry. Two complementary words form a valid initial checksum for
        # every possible checksum field, without using the packet builder.
        for original in range(65536):
            quote = bytearray(20)
            quote[:2] = (65535 - original).to_bytes(2, "big")
            quote[10:12] = original.to_bytes(2, "big")
            before = bytes(quote)
            self.assertEqual(sum(int.from_bytes(quote[i:i + 2], "big")
                for i in range(0, 20, 2)) % 65535, 0)
            corrupt_quote_checksum(quote)
            self.assertEqual(sum(int.from_bytes(quote[i:i + 2], "big")
                for i in range(0, 20, 2)) % 65535, 256, hex(original))
            self.assertEqual(checksum(quote), 0xfeff, hex(original))
            self.assertEqual(quote[:10] + quote[12:], before[:10] + before[12:])

    def test_real_packet_corruption_is_lane_independent_not_xor_sign_dependent(self):
        udp = struct.pack("!HHHH", 41000, PORT, 16, 0) + b"12345678"
        original_high_bits = set()
        for source, destination, ident in (
            ("192.0.2.9", "198.51.100.2", 0),
            ("198.18.20.50", "198.18.10.254", 1),
            ("198.18.10.1", "198.18.10.2", 255),
            ("198.18.10.1", "198.18.10.2", 256),
            ("203.0.113.1", "192.0.2.9", 65535),
        ):
            packet = ip_packet(source, destination, 17, udp, ident)
            original_high_bits.add(packet[10] & 1)
            response = error_packet(packet, ipv4(packet), "bad-quote-checksum", destination, 28928)
            self.assertEqual(checksum(response[:20]), 0)
            self.assertEqual(checksum(response[20:]), 0)
            self.assertEqual(checksum(response[28:48]), 0xfeff)
            self.assertEqual(response[28:38], packet[:10])
            self.assertEqual(response[40:48], packet[12:20])
        self.assertEqual(original_high_bits, {0, 1})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("peer", "client"):
        command = subparsers.add_parser(name)
        command.add_argument("--interface", required=True)
        command.add_argument("--bind", required=True)
        if name == "peer":
            command.add_argument("--error-source")
            command.add_argument("--control-directory", help="Root-controlled test hold/release directory")
        else:
            command.add_argument("--target", required=True)
            command.add_argument("--expected-error-source")
            command.add_argument("--source-port", type=int, default=41000)
            command.add_argument("--timeout", type=float, default=1.5)
            command.add_argument("--profile", choices=("related", "explicit-allow", "stateful-off", "stateful-off-allow", "explicit-deny", "block-icmp") + HELD, default="related")
    subparsers.add_parser("selftest")
    args = parser.parse_args()
    if args.command == "peer":
        peer(args)
    elif args.command == "client":
        client(args)
    else:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(OfflineOracles)
        raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())


if __name__ == "__main__":
    main()
