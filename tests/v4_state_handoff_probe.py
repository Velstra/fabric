"""Real-kernel IPv4 tail-stage fault injection in a disposable network namespace.

Run as root with --binary pointing to the freshly built agent. The fixture
starts its own agent and mutates only maps referenced by that child. It never
selects existing machine-wide maps by name, attaches to an existing interface,
or treats source inspection as a packet test.
"""

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import socket
import struct
import subprocess
import sys
import tempfile
import time


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


class Lookup(ctypes.Structure):
    _fields_ = [("fd", ctypes.c_uint32), ("pad", ctypes.c_uint32),
                ("key", ctypes.c_uint64), ("value", ctypes.c_uint64),
                ("flags", ctypes.c_uint64)]


class Run(ctypes.Structure):
    _fields_ = [(name, kind) for name, kind in (
        ("fd", ctypes.c_uint32), ("retval", ctypes.c_uint32),
        ("data_size_in", ctypes.c_uint32), ("data_size_out", ctypes.c_uint32),
        ("data_in", ctypes.c_uint64), ("data_out", ctypes.c_uint64),
        ("repeat", ctypes.c_uint32), ("duration", ctypes.c_uint32),
        ("ctx_size_in", ctypes.c_uint32), ("ctx_size_out", ctypes.c_uint32),
        ("ctx_in", ctypes.c_uint64), ("ctx_out", ctypes.c_uint64),
        ("flags", ctypes.c_uint32), ("cpu", ctypes.c_uint32),
        ("batch_size", ctypes.c_uint32))]


class State(ctypes.Structure):
    _fields_ = [(name, kind) for name, kind in (
        ("epoch", ctypes.c_uint64), ("rule", ctypes.c_uint64),
        ("frame_len", ctypes.c_uint64), ("ifindex", ctypes.c_uint32),
        ("policy_id", ctypes.c_uint32), ("vni", ctypes.c_uint32),
        ("default_action", ctypes.c_uint32), ("flags", ctypes.c_uint32),
        ("src_addr", ctypes.c_ubyte * 4), ("dst_addr", ctypes.c_ubyte * 4),
        ("checksum", ctypes.c_uint16), ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16), ("total_len", ctypes.c_uint16),
        ("ihl_bytes", ctypes.c_uint16), ("proto", ctypes.c_uint8),
        ("ttl", ctypes.c_uint8), ("icmp_type", ctypes.c_uint8),
        ("blocklisted", ctypes.c_uint8), ("local_dhcp", ctypes.c_uint8),
        ("valid", ctypes.c_uint8))]


class Kernel:
    def __init__(self):
        need(platform.machine() == "x86_64" and os.geteuid() == 0,
             "this fixture requires disposable x86_64 VM root")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long
        self.fds = []
        self.cpu = min(os.sched_getaffinity(0))
        # XDP test-run has no TEST_RUN_ON_CPU flag on the supported kernels.
        # Pin this isolated fixture process so consecutive per-CPU handoffs
        # are exercised on the same CPU without invoking live-frame delivery.
        os.sched_setaffinity(0, {self.cpu})
        possible = Path("/sys/devices/system/cpu/possible").read_text().strip()
        self.cpus = sum(int(part.split("-")[-1]) - int(part.split("-")[0]) + 1
                        for part in possible.split(","))

    def call(self, command, attr):
        result = self.libc.syscall(321, command, ctypes.byref(attr), ctypes.sizeof(attr))
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return result

    def fd(self, command, identifier):
        attr = ctypes.create_string_buffer(struct.pack("<III", identifier, 0, 0))
        fd = self.call(command, attr)
        self.fds.append(fd)
        return fd

    def value(self, fd, size, value=None, key=0, delete=False):
        key_buffer = ctypes.create_string_buffer(key if isinstance(key, bytes) else struct.pack("<I", key))
        buffer = ctypes.create_string_buffer(size) if value is None else ctypes.create_string_buffer(value)
        need(value is None or len(value) == size, "map value length mismatch")
        attr = Lookup(fd=fd, key=ctypes.addressof(key_buffer),
                      value=0 if delete else ctypes.addressof(buffer))
        self.call(3 if delete else 1 if value is None else 2, attr)
        return buffer.raw[:size]

    def packet(self, fd, packet, ifindex):
        source = ctypes.create_string_buffer(packet)
        output = ctypes.create_string_buffer(4096)
        context = ctypes.create_string_buffer(struct.pack("<6I", 0, len(packet), 0, ifindex, 0, 0))
        attr = Run(fd=fd, data_size_in=len(packet), data_size_out=len(output),
                   data_in=ctypes.addressof(source), data_out=ctypes.addressof(output),
                   repeat=1, ctx_size_in=24, ctx_in=ctypes.addressof(context))
        self.call(10, attr)
        return attr.retval, output.raw[:attr.data_size_out]

    def close(self):
        for fd in self.fds:
            os.close(fd)


def owned_objects(pid):
    identifiers = {"map": set(), "prog": set()}
    for path in Path(f"/proc/{pid}/fdinfo").iterdir():
        try:
            lines = path.read_text().splitlines()
        except FileNotFoundError:
            # The live daemon may close unrelated descriptors while procfs is
            # enumerated. Required BPF objects are still checked below by ID;
            # never substitute a globally named object for a missing one.
            continue
        for line in lines:
            for kind in identifiers:
                if line.startswith(kind + "_id:"):
                    identifiers[kind].add(int(line.split()[1]))
    result = {}
    for kind, ids in identifiers.items():
        result[kind] = {}
        for identifier in ids:
            info = json.loads(subprocess.check_output(
                ["bpftool", "-j", kind, "show", "id", str(identifier)]))
            if isinstance(info, list):
                need(len(info) == 1, "ambiguous child-owned BPF object")
                info = info[0]
            name = info["name"]
            need(name not in result[kind], "ambiguous child-owned object name: " + name)
            result[kind][name] = info
    return result


def udp_packet():
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 1, 0, 64, 17, 0,
                                   socket.inet_aton("192.0.2.2"), socket.inet_aton("198.51.100.2")))
    total = sum(struct.unpack("!10H", header))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    struct.pack_into("!H", header, 10, total ^ 65535)
    return bytes.fromhex("0200000000010200000000020800") + header + struct.pack("!4H", 40000, 9999, 8, 0)


def checksum(data):
    data += b"\0" if len(data) % 2 else b""
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return total ^ 65535


def transport_packet(proto, source, destination, source_port=0, destination_port=0,
                     flags=0, sequence=0, acknowledgement=0, icmp_type=8):
    source = socket.inet_aton(source)
    destination = socket.inet_aton(destination)
    if proto == 6:
        payload = bytearray(struct.pack("!HHIIBBHHH", source_port, destination_port, sequence,
                                        acknowledgement, 0x50, flags, 4096, 0, 0))
        pseudo = source + destination + struct.pack("!BBH", 0, proto, len(payload))
        struct.pack_into("!H", payload, 16, checksum(pseudo + payload))
    elif proto == 17:
        payload = struct.pack("!4H", source_port, destination_port, 8, 0)
    else:
        payload = bytearray(struct.pack("!BBHHH", icmp_type, 0, 0, 12345, 1))
        struct.pack_into("!H", payload, 2, checksum(payload))
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0,
                                   64, proto, 0, source, destination))
    struct.pack_into("!H", header, 10, checksum(header))
    return bytes.fromhex("0200000000010200000000020800") + header + payload


def ipv4_variant(frame, options=b"", fragment=0, padding=b"", total_length=None, ihl=None):
    """Vary IPv4 framing while retaining a correct checksum for present headers."""
    need(len(options) % 4 == 0 and len(options) <= 40, "invalid fixture options")
    header = bytearray(frame[14:34] + options)
    header[0] = 0x40 | ((len(header) // 4) if ihl is None else ihl)
    struct.pack_into("!H", header, 2, len(frame) - 14 + len(options) if total_length is None else total_length)
    struct.pack_into("!H", header, 6, fragment)
    struct.pack_into("!H", header, 10, 0)
    struct.pack_into("!H", header, 10, checksum(header))
    return frame[:14] + header + frame[34:] + padding


def exercise(pid, interface):
    objects = owned_objects(pid)
    kernel = Kernel()
    try:
        def map_fd(name, size, kind=None):
            info = objects["map"][name]
            need(info["bytes_value"] == size and (kind is None or info["type"] == kind),
                 "unexpected handoff map ABI: " + name)
            return kernel.fd(14, info["id"])

        need(ctypes.sizeof(State) == 72 and State.valid.offset == 67, "unexpected host fixture ABI")
        scratch = map_fd("V4_STATE_SCRATC", 72, "percpu_array")
        epoch = map_fd("CONFIG_EPOCH", 8, "array")
        packet_epoch = map_fd("PACKET_EPOCH", 8, "percpu_array")
        ready = map_fd("APPLY_STATE", 4, "array")
        programs = map_fd("V4_STATE_PROGS", 4, "prog_array")
        ha = map_fd("HA_IFACES", 1, "hash")
        ingress = kernel.fd(13, objects["prog"]["velstra"]["id"])
        stage_info = objects["prog"].get("velstra_v4_state", objects["prog"].get("velstra_v4_stat"))
        need(stage_info is not None, "missing child-owned IPv4 state stage")
        stage = kernel.fd(13, stage_info["id"])
        packet = udp_packet()
        ifindex = socket.if_nametoindex(interface)
        results = []

        def check(name, passed):
            need(passed, name)
            results.append(name)
            print("PASSED " + name, flush=True)

        ordinary = kernel.packet(ingress, packet, ifindex)
        need(ordinary == (2, packet),
             "ordinary IPv4 packet differs: " + json.dumps({
                 "kernel": platform.release(), "action": ordinary[0],
                 "input": packet.hex(), "output": ordinary[1].hex(),
                 "ready": kernel.value(ready, 4).hex(),
                 "epoch": kernel.value(epoch, 8).hex(),
             }))
        check("ordinary IPv4 packet passes unchanged", True)
        width = 72 * kernel.cpus
        original = kernel.value(scratch, width)
        start = kernel.cpu * 72
        state = State.from_buffer_copy(original[start:start + 72])
        check("normal handoff consumed", state.valid == 0 and state.ifindex == ifindex and state.frame_len == len(packet))

        def set_state(**changes):
            value = bytearray(original)
            state = State.from_buffer(value, start)
            state.valid = 1
            for key, value_in in changes.items():
                setattr(state, key, value_in)
            kernel.value(scratch, width, bytes(value))

        def consumed():
            return kernel.value(scratch, width)[start + State.valid.offset] == 0

        for name, changes in (
            ("absent handoff", {"valid": 0}), ("invalid validity tag", {"valid": 2}),
            ("wrong interface", {"ifindex": ifindex + 1}),
            ("wrong frame length", {"frame_len": len(packet) + 1}),
            ("invalid IPv4 header length", {"ihl_bytes": 19}),
            ("unaligned IPv4 header length", {"ihl_bytes": 21}),
            ("truncated IPv4 options", {"ihl_bytes": 60}),
            ("total length below header length", {"total_len": 19}),
            ("total length beyond packet bytes", {"total_len": len(packet)}),
            ("invalid blocklist flag", {"blocklisted": 2}),
            ("invalid DHCP flag", {"local_dhcp": 2}),
            ("stale handoff epoch", {"epoch": state.epoch + 2}),
        ):
            set_state(**changes)
            check(name + " drops and consumes", kernel.packet(stage, packet, ifindex)[0] == 1 and consumed())
        set_state()
        check("valid one-shot handoff passes", kernel.packet(stage, packet, ifindex) == (2, packet) and consumed())
        check("replayed consumed handoff drops", kernel.packet(stage, packet, ifindex)[0] == 1)
        for name, fd, size, changed in (
            ("changed configuration generation", epoch, 8, struct.pack("<Q", state.epoch + 2)),
            ("configuration not ready", ready, 4, struct.pack("<I", 1)),
        ):
            previous = kernel.value(fd, size)
            try:
                set_state()
                kernel.value(fd, size, changed)
                check(name + " drops", kernel.packet(stage, packet, ifindex)[0] == 1 and consumed())
            finally:
                kernel.value(fd, size, previous)
        previous = kernel.value(packet_epoch, 8 * kernel.cpus)
        changed = bytearray(previous)
        struct.pack_into("<Q", changed, kernel.cpu * 8, state.epoch + 2)
        try:
            set_state()
            kernel.value(packet_epoch, len(changed), bytes(changed))
            check("mismatched source generation drops", kernel.packet(stage, packet, ifindex)[0] == 1 and consumed())
        finally:
            kernel.value(packet_epoch, len(previous), previous)
        try:
            set_state()
            kernel.value(ha, 1, b"\1", key=ifindex)
            check("new HA fence drops", kernel.packet(stage, packet, ifindex)[0] == 1 and consumed())
        finally:
            kernel.value(ha, 1, key=ifindex, delete=True)
        try:
            kernel.value(programs, 4, delete=True)
            set_state()
            check("missing tail stage drops and invalidates", kernel.packet(ingress, packet, ifindex)[0] == 1 and consumed())
        finally:
            kernel.value(programs, 4, struct.pack("<I", stage))
        check("restored tail stage recovers", kernel.packet(ingress, packet, ifindex) == (2, packet))

        # Exercise real state transitions through the full ingress chain, not
        # just synthesized handoff metadata. Only this child-owned policy map
        # changes, and both directions traverse the actual packet program.
        config = map_fd("CONFIG", 8, "hash")
        flows = map_fd("FW_FLOWS", 24, "lru_hash")
        need(objects["map"]["FW_FLOWS"]["bytes_key"] == 44, "unexpected firewall key ABI")
        previous = kernel.value(config, 8)
        _, original_flags = struct.unpack("<II", previous)
        packet_failures = []

        def policy(action, extra=0):
            kernel.value(config, 8, struct.pack("<II", action, original_flags | 4 | extra))

        def packet_check(name, frame, action=2):
            result = kernel.packet(ingress, frame, ifindex)
            if result[0] == action and (action != 2 or result[1] == frame):
                check(name, True)
            else:
                packet_failures.append(name)
                print(f"FAILED {name}: action={result[0]}, expected={action}", flush=True)

        local, peer = "192.0.2.20", "198.51.100.20"

        def flow_pair(source_port):
            def key(source, destination, sport, dport):
                return struct.pack("<I16s16sHHBB2x", 0, socket.inet_aton(source),
                                   socket.inet_aton(destination), sport, dport, 6, 4)

            values = []
            for flow_key in (key(local, peer, source_port, 443), key(peer, local, 443, source_port)):
                try:
                    values.append(kernel.value(flows, 24, key=flow_key))
                except OSError as error:
                    if error.errno != errno.ENOENT:
                        raise
                    values.append(None)
            return tuple(values)

        try:
            policy(0)
            datagram = transport_packet(17, local, peer, 42000, 7777)
            for name, frame in (
                ("valid Ethernet padding retained", ipv4_variant(datagram, padding=bytes(18))),
                ("valid IPv4 options retained", ipv4_variant(datagram, options=bytes(4))),
                ("valid first fragment retained", ipv4_variant(datagram, fragment=0x2000)),
                ("valid later fragment retained", ipv4_variant(datagram, fragment=1)),
            ):
                packet_check(name, frame)
            for name, frame in (
                ("truncated IPv4 header dropped", ipv4_variant(datagram, ihl=15)),
                ("IPv4 total length below IHL dropped", ipv4_variant(datagram, total_length=19)),
                ("IPv4 total length beyond available bytes dropped", ipv4_variant(datagram, total_length=29)),
            ):
                packet_check(name, frame, 1)
            packet_check("stateful TCP SYN admitted", transport_packet(6, local, peer, 41000, 443, 2, 100))
            policy(1)
            packet_check("stateful TCP SYN ACK admitted under default deny",
                         transport_packet(6, peer, local, 443, 41000, 18, 200, 101))
            packet_check("stateful TCP ACK admitted under default deny",
                         transport_packet(6, local, peer, 41000, 443, 16, 101, 201))
            packet_check("untracked TCP ACK denied",
                         transport_packet(6, local, peer, 41001, 443, 16, 101, 201), 1)
            policy(0)
            # An invalid *opener* does not create tracked state. An untracked
            # packet still faces ordinary policy; this is not a universal
            # drop-invalid policy. Invalid transitions of existing flows are
            # independently required to drop without refreshing either key.
            check("invalid TCP opener starts without either state key", flow_pair(41002) == (None, None))
            packet_check("untracked SYN FIN follows default allow without packet mutation",
                         transport_packet(6, local, peer, 41002, 443, 3, 100))
            check("allowed invalid TCP opener creates no state", flow_pair(41002) == (None, None))
            policy(1)
            packet_check("untracked SYN FIN follows default deny",
                         transport_packet(6, local, peer, 41002, 443, 3, 100), 1)
            check("denied invalid TCP opener creates no state", flow_pair(41002) == (None, None))
            policy(0)
            before = flow_pair(41000)
            check("valid TCP handshake created both state keys", all(value is not None for value in before))
            packet_check("tracked invalid SYN FIN denied despite default allow",
                         transport_packet(6, local, peer, 41000, 443, 3, 100), 1)
            check("denied invalid transition leaves both states unchanged", flow_pair(41000) == before)
            packet_check("stateful UDP opener admitted", transport_packet(17, local, peer, 43000, 7777))
            policy(1)
            packet_check("stateful UDP reply admitted under default deny",
                         transport_packet(17, peer, local, 7777, 43000))
            packet_check("untracked UDP reply denied", transport_packet(17, peer, local, 7777, 43001), 1)
            policy(0)
            packet_check("stateful ICMP echo request admitted", transport_packet(1, local, peer))
            policy(1)
            packet_check("stateful ICMP echo reply admitted under default deny",
                         transport_packet(1, peer, local, icmp_type=0))
            policy(1, 1)
            packet_check("explicit ICMP deny overrides tracked echo reply",
                         transport_packet(1, peer, local, icmp_type=0), 1)
        finally:
            kernel.value(config, 8, previous)
        need(not packet_failures, "packet conformance failures: " + ", ".join(packet_failures))
        return results
    finally:
        kernel.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--namespace-child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    need(os.geteuid() == 0, "run the disposable fixture as root")
    if not args.namespace_child:
        env = {**os.environ, "VELSTRA_HANDOFF_PARENT_NS": os.readlink("/proc/self/ns/net"),
               "VELSTRA_HANDOFF_PARENT_MNT": os.readlink("/proc/self/ns/mnt")}
        subprocess.run(["unshare", "--mount", "--net", "--", sys.executable, __file__, "--binary", str(binary),
                        "--namespace-child"], env=env, check=True)
        return
    need(os.environ.get("VELSTRA_HANDOFF_PARENT_NS") not in (None, os.readlink("/proc/self/ns/net")),
         "refusing mutations outside a fresh network namespace")
    need(os.environ.get("VELSTRA_HANDOFF_PARENT_MNT") not in (None, os.readlink("/proc/self/ns/mnt")),
         "refusing sysfs mount outside a fresh mount namespace")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "sysfs", "sysfs", "/sys"], check=True)
    interface = "handoff0"
    with tempfile.TemporaryDirectory(prefix="fabric-handoff-") as directory:
        root = Path(directory)
        config = root / "config.toml"
        config.write_text('default_action = "pass"\nsource_validation = "strict"\n')
        subprocess.run(["ip", "link", "add", interface, "type", "veth", "peer", "name", "handoff-peer"], check=True)
        subprocess.run(["ip", "link", "set", "handoff-peer", "up"], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        with (root / "agent.log").open("wb") as log:
            process = subprocess.Popen([str(binary), "run", "--iface", interface, "--config", str(config),
                                        "--stats-interval", "0"], stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 90
                while b"Velstra is live" not in (root / "agent.log").read_bytes():
                    need(process.poll() is None and time.monotonic() < deadline,
                         "agent failed to load: " + (root / "agent.log").read_text())
                    time.sleep(.1)
                results = exercise(process.pid, interface)
                print(json.dumps({"kernel": platform.release(), "passed": results}))
            finally:
                process.terminate()
                process.wait(timeout=15)


if __name__ == "__main__":
    main()
