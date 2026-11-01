#!/usr/bin/env python3
"""Prepare native state tests without root, then run only the kernel checks as root."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


CASES = {
    "rule_contexts_kernel::production_independent_rule_contexts": "ACTUAL_INDEPENDENT_RULE_CONTEXTS ",
    "ipv6_state_kernel::production_ipv6_protocol_state_and_rule_limits": "ACTUAL_IPV6_PROTOCOL_STATE ",
    "native_flow_store_in_packaged_datapath": "ACTUAL_PACKAGED_FLOW_CONTROL ",
    "native_flow_store_rejects_incompatible_maps": "ACTUAL_PACKAGED_FLOW_SCHEMA ",
    "native_policy_scope_lifecycle_and_restart": "ACTUAL_POLICY_SCOPE_LIFECYCLE ",
    "native_agent_state_gc_end_to_end": "ACTUAL_AGENT_STATE_GC ",
    "native_flow_scan_initialized_prefix": "ACTUAL_INITIALIZED_FLOW_SCAN ",
    "synproxy_kernel::production_synproxy_server_handshake_validation": "ACTUAL_SYNPROXY_HANDSHAKE ",
    "synproxy_kernel::production_synproxy_protection_never_fails_open": "ACTUAL_SYNPROXY_FAIL_CLOSED ",
    "synproxy_kernel::production_synproxy_ipv4_options_cannot_bypass_protection": "ACTUAL_SYNPROXY_OPTIONS_CLOSED ",
    "synproxy_kernel::production_synproxy_mss_negotiation_respects_client_limit": "ACTUAL_SYNPROXY_MSS ",
    "guest_policy_kernel::production_ipv6_decap_guest_policy": "ACTUAL_IPV6_DECAP_GUEST_POLICY ",
    "guest_policy_kernel::production_tunnel_ingress_boundary": "ACTUAL_TUNNEL_INGRESS_BOUNDARY ",
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(destination):
    repo = Path(__file__).resolve().parents[2]
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version=1", "--locked"],
        cwd=repo, text=True,
    ))
    package = next(item["id"] for item in metadata["packages"] if item["name"] == "velstra")
    result = subprocess.run(
        ["cargo", "test", "-p", "velstra", "--test", "flow_store_kernel",
         "--locked", "--no-run", "--message-format=json"],
        cwd=repo, stdout=subprocess.PIPE, text=True, check=False,
    )
    messages = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    for message in messages:
        if message.get("reason") == "compiler-message":
            rendered = message["message"].get("rendered")
            if rendered:
                print(rendered, file=sys.stderr, end="")
    if result.returncode:
        raise RuntimeError("building native firewall state tests failed")
    binaries = [Path(item["executable"]) for item in messages
                if item.get("reason") == "compiler-artifact"
                and item.get("package_id") == package
                and item["target"]["name"] == "flow_store_kernel"
                and item.get("executable")]
    agents = [Path(item["executable"]) for item in messages
              if item.get("reason") == "compiler-artifact"
              and item.get("package_id") == package
              and item["target"]["name"] == "velstra"
              and "bin" in item["target"]["kind"]
              and item.get("executable")]
    outputs = [Path(item["out_dir"]) / "velstra" for item in messages
               if item.get("reason") == "build-script-executed"
               and item.get("package_id") == package]
    if len(binaries) != 1 or len(outputs) != 1 or len(agents) != 1:
        raise RuntimeError("Cargo did not identify exactly one test binary, agent and embedded datapath")
    binary, object_file = binaries[0].resolve(), outputs[0].resolve()
    header = object_file.read_bytes()[:20]
    if header[:4] != b"\x7fELF" or header[5] not in (1, 2):
        raise RuntimeError("embedded datapath is not an ELF object")
    byteorder = "little" if header[5] == 1 else "big"
    if int.from_bytes(header[18:20], byteorder) != 247:
        raise RuntimeError("embedded datapath is not an eBPF object")
    manifest = {
        "version": 2,
        "agent": str(agents[0].resolve()),
        "agentSHA256": digest(agents[0]),
        "binary": str(binary),
        "object": str(object_file),
        "binarySHA256": digest(binary),
        "objectSHA256": digest(object_file),
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(manifest, indent=2) + "\n")
    temporary.replace(destination)
    print(f"Prepared {len(CASES)} native kernel checks: {destination}")


def run(manifest_path):
    if os.geteuid() != 0:
        raise RuntimeError("kernel checks require root; preparation must run without sudo")
    manifest = json.loads(manifest_path.read_text())
    expected = {"version", "binary", "object", "agent", "binarySHA256", "objectSHA256", "agentSHA256"}
    if set(manifest) != expected or manifest["version"] != 2:
        raise RuntimeError("incompatible native test manifest")
    binary, object_file = Path(manifest["binary"]), Path(manifest["object"])
    if digest(binary) != manifest["binarySHA256"] or digest(object_file) != manifest["objectSHA256"] or digest(Path(manifest["agent"])) != manifest["agentSHA256"]:
        raise RuntimeError("native test artifacts changed after preparation")
    environment = os.environ.copy()
    environment["VELSTRA_CONTROL_PRODUCTION_OBJECT"] = str(object_file)
    environment["VELSTRA_CONTROL_AGENT_BINARY"] = manifest["agent"]
    for case, marker in CASES.items():
        result = subprocess.run(
            [str(binary), "--ignored", "--exact", case, "--nocapture"],
            env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False,
        )
        print(result.stdout, end="", flush=True)
        if result.returncode or "1 passed; 0 failed; 0 ignored;" not in result.stdout:
            raise RuntimeError(f"native kernel check did not execute successfully: {case}")
        reports = [json.loads(line.split(marker, 1)[1])
                   for line in result.stdout.splitlines() if marker in line]
        if len(reports) != 1 or reports[0].get("result") != "PASS":
            raise RuntimeError(f"native kernel check returned no unique success report: {case}")
    print("NATIVE_FLOW_STORE_CI " + json.dumps({
        "result": "PASS", "tests": len(CASES), "objectSHA256": manifest["objectSHA256"],
    }), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--prepare", type=Path)
    mode.add_argument("--run", type=Path)
    args = parser.parse_args()
    if args.prepare:
        prepare(args.prepare)
    else:
        run(args.run)


if __name__ == "__main__":
    main()
