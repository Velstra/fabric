"""Disposable-VM stale occupancy fixture. Never imported to mutate a live map.

Fill accepts only an empty, explicit FW_FLOWS map of the reviewed layout.
Clear removes only the exact stale values this fixture owns; it never flushes
a map. Production capacity is observed separately through the actual agent.
"""

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import secrets
import stat
import struct
import subprocess


KEY = struct.Struct("<I16s16sHHBB2x")
VALUE = struct.Struct("<QQII")
STALE_VALUE = VALUE.pack(0, 604_800_000_000_000, 3, 0)
MAX_ENTRIES = 65_536
CHUNK = 1024


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def metadata(map_id):
    result = subprocess.run(["bpftool", "-j", "map", "show", "id", str(map_id)],
                            check=True, capture_output=True, timeout=10, text=True)
    info = json.loads(result.stdout)
    if isinstance(info, list):
        need(len(info) == 1, "ambiguous map identity")
        info = info[0]
    validate_metadata(info, map_id)
    return info


def validate_metadata(info, map_id):
    need(type(map_id) is int and map_id > 0, "explicit positive map ID required")
    need(info.get("id") == map_id and info.get("name") == "FW_FLOWS"
         and info.get("type") == "lru_hash", "not the selected FW_FLOWS LRU")
    need(info.get("bytes_key") == KEY.size and info.get("bytes_value") == VALUE.size
         and info.get("max_entries") == MAX_ENTRIES,
         "FW_FLOWS ABI/capacity differs from this disposable fixture")


def raw_count(map_id):
    # Independent bpftool enumeration, not the new agent's counting code.
    result = subprocess.run(["bpftool", "-j", "map", "dump", "id", str(map_id)],
                            check=True, capture_output=True, timeout=30, text=True)
    entries = json.loads(result.stdout)
    need(isinstance(entries, list), "unexpected independent kernel dump")
    return len(entries)


def fixture_key(index, nonce):
    need(type(index) is int and 0 <= index < MAX_ENTRIES, "invalid fixture key index")
    need(type(nonce) is int and 0 <= nonce <= 0xFFFFFFFF, "invalid fixture identity")
    source = bytes([192, 0, 2, 123]) + bytes(12)
    target = bytes([198, 18, index >> 8, index & 255]) + bytes(12)
    return KEY.pack(0xFFFF0000 | (nonce & 0xFFFF), source, target,
                    40000 + (nonce % 20000), 9, 6, 4)


class Batch(ctypes.Structure):
    _fields_ = [(name, kind) for name, kind in (
        ("in_batch", ctypes.c_uint64), ("out_batch", ctypes.c_uint64),
        ("keys", ctypes.c_uint64), ("values", ctypes.c_uint64),
        ("count", ctypes.c_uint32), ("map_fd", ctypes.c_uint32),
        ("elem_flags", ctypes.c_uint64), ("flags", ctypes.c_uint64))]


class Lookup(ctypes.Structure):
    _fields_ = [("map_fd", ctypes.c_uint32), ("pad", ctypes.c_uint32),
                ("key", ctypes.c_uint64), ("value", ctypes.c_uint64),
                ("flags", ctypes.c_uint64)]


class Kernel:
    def __init__(self, map_id):
        need(platform.machine() == "x86_64" and os.geteuid() == 0,
             "disposable x86_64 VM root required")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long
        # UAPI BPF_MAP_GET_FD_BY_ID=14, map_id/next_id/open_flags union.
        attr = ctypes.create_string_buffer(struct.pack("<III", map_id, 0, 0))
        self.fd = self.call(14, attr)

    def call(self, command, attr, missing=False):
        result = self.libc.syscall(321, command, ctypes.byref(attr), ctypes.sizeof(attr))
        if result < 0:
            error = ctypes.get_errno()
            if missing and error == errno.ENOENT:
                return None
            raise OSError(error, os.strerror(error))
        return result

    def insert(self, key, value):
        need(len(key) == KEY.size and len(value) == VALUE.size, "invalid fixture key/value width")
        key_buffer = ctypes.create_string_buffer(key)
        value_buffer = ctypes.create_string_buffer(value)
        attr = Lookup(map_fd=self.fd, key=ctypes.addressof(key_buffer),
                      value=ctypes.addressof(value_buffer), flags=1)
        # BPF_MAP_UPDATE_ELEM preserves BPF_NOEXIST. Kernel6.12's generic
        # update-batch rejects that flag; never substitute overwriting BPF_ANY.
        self.call(2, attr)

    def batch(self, command, keys):
        need(command == 27, "only ownership-checked batch deletion is permitted")
        need(1 <= len(keys) <= CHUNK and all(len(key) == KEY.size for key in keys),
             "invalid deletion batch")
        key_buffer = ctypes.create_string_buffer(b"".join(keys))
        attr = Batch(keys=ctypes.addressof(key_buffer), count=len(keys), map_fd=self.fd)
        self.call(command, attr)
        need(attr.count == len(keys), "partial fixture batch; ownership state retained")

    def lookup(self, key):
        key_buffer = ctypes.create_string_buffer(key)
        value_buffer = ctypes.create_string_buffer(VALUE.size)
        attr = Lookup(map_fd=self.fd, key=ctypes.addressof(key_buffer),
                      value=ctypes.addressof(value_buffer))
        if self.call(1, attr, missing=True) is None:  # BPF_MAP_LOOKUP_ELEM.
            return None
        return value_buffer.raw

    def close(self):
        os.close(self.fd)


def validate_state(state, map_id):
    need(isinstance(state, dict) and set(state) == {"version", "map_id", "count", "nonce"},
         "invalid fixture ownership state")
    need(type(state["version"]) is int and state["version"] == 1
         and type(state["map_id"]) is int and state["map_id"] == map_id,
         "fixture state belongs to another map")
    need(type(state["count"]) is int and 1 <= state["count"] <= MAX_ENTRIES,
         "invalid fixture entry count")
    fixture_key(0, state["nonce"])


def state_path(text):
    path = Path(text)
    need(path.parent == Path("/run") and path.name.startswith("qa-capacity-")
         and path.suffix == ".json", "ownership file must be /run/qa-capacity-*.json")
    return path


def execute(args):
    need(args.allow_disposable_map_mutation, "explicit disposable-map mutation permission required")
    need(platform.machine() == "x86_64" and os.geteuid() == 0,
         "disposable x86_64 VM root required")
    info = metadata(args.map_id)
    path = state_path(args.state)
    kernel = Kernel(args.map_id)
    try:
        if args.command == "fill":
            need(type(args.count) is int and 1 <= args.count <= MAX_ENTRIES, "invalid fill count")
            need(raw_count(args.map_id) == 0, "refusing to fill a nonempty map")
            state = dict(version=1, map_id=args.map_id, count=args.count, nonce=secrets.randbits(32))
            # Ownership precedes all writes, so a partially failed fill can be
            # safely cleared. Never replace another fixture's recovery record.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as output:
                json.dump(state, output)
                output.flush()
                os.fsync(output.fileno())
            for index in range(args.count):
                kernel.insert(fixture_key(index, state["nonce"]), STALE_VALUE)
            count = raw_count(args.map_id)
            need(count == args.count, "independent raw occupancy disagrees; possible concurrent writes")
            return dict(map_id=args.map_id, max_entries=info["max_entries"], inserted=args.count,
                        raw_count=count, stale_age_seconds=604800)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as source:
            meta = os.fstat(source.fileno())
            need(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_mode & 0o077 == 0
                 and meta.st_size <= 4096, "unsafe fixture ownership state")
            state = json.load(source)
        validate_state(state, args.map_id)
        keys = []
        for index in range(state["count"]):
            key = fixture_key(index, state["nonce"])
            value = kernel.lookup(key)
            need(value in (None, STALE_VALUE), "fixture key changed; refusing to delete foreign state")
            if value is not None:
                keys.append(key)
        # Validate all ownership before deleting the first entry.
        for first in range(0, len(keys), CHUNK):
            kernel.batch(27, keys[first:first + CHUNK])  # BPF_MAP_DELETE_BATCH.
        count = raw_count(args.map_id)
        path.unlink()
        return dict(map_id=args.map_id, max_entries=info["max_entries"], removed=len(keys), raw_count=count)
    finally:
        kernel.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("fill", "clear"))
    parser.add_argument("--map-id", type=int, required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--count", type=int)
    parser.add_argument("--allow-disposable-map-mutation", action="store_true")
    args = parser.parse_args()
    print(json.dumps(execute(args), sort_keys=True))


if __name__ == "__main__":
    main()
