#!/usr/bin/env python3
"""Release only the explicitly selected standalone public library."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import time
import tomllib
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
POLICY = tomllib.loads((ROOT / "crate-release.toml").read_text())


def require(value, message):
    if not value:
        raise ValueError(message)


def run(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def metadata():
    data = json.loads(run("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"))
    packages = [p for p in data["packages"] if p["name"] == POLICY["package"]]
    require(len(packages) == 1, "selected package missing or ambiguous")
    package = packages[0]
    require(Path(package["manifest_path"]).resolve() == ROOT / POLICY["manifest"],
            "package manifest identity mismatch")
    validate_package(package)
    return package, Path(data["target_directory"])


def validate_package(package):
    require(package["name"] == POLICY["package"], "package not allowlisted")
    require(package.get("publish") == ["crates-io"], "explicit crates.io-only permission required")
    require(package.get("repository", "").lower() == POLICY["repository"].lower(),
            "repository mismatch")
    require(package.get("license") == POLICY["license"], "license mismatch")
    require(all(t["kind"] in (["lib"], ["custom-build"], ["test"], ["example"], ["bench"])
                for t in package["targets"]), "only a standalone library may be published")
    require(any(t["kind"] == ["lib"] for t in package["targets"]), "library required")
    for dependency in package["dependencies"]:
        require(not dependency.get("path") and
                dependency.get("source") == "registry+https://github.com/rust-lang/crates.io-index",
                "git/path/private dependencies require a separate reviewed publication plan")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", package["version"]),
            "invalid release version")


def version_for_event(package, env):
    version = package["version"]
    requested = env.get("REQUESTED_VERSION", "")
    if env.get("GITHUB_EVENT_NAME") == "workflow_dispatch":
        require(requested == version, "requested version must exactly match Cargo.toml")
    if env.get("GITHUB_REF", "").startswith("refs/tags/"):
        require(env["GITHUB_REF"] == "refs/tags/v" + version, "tag/package version mismatch")
    return version


def publication_context(env, head):
    require(env.get("GITHUB_REPOSITORY") == POLICY["github"], "unexpected repository")
    require(env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("PUBLISH_REQUESTED") == "true"
            and env.get("GITHUB_RUN_ATTEMPT") == "1", "explicit first-attempt main publication required")
    require(env.get("GITHUB_SHA") == head, "checkout must match the workflow source")


def registry(path):
    request = Request("https://crates.io/api/v1/" + path,
                      headers={"User-Agent": "Velstra-crate-release/1.0 (" + POLICY["repository"] + ")"})
    try:
        with urlopen(request, timeout=30) as response:
            payload = response.read(4 * 1024 * 1024 + 1)
            require(len(payload) <= 4 * 1024 * 1024, "registry response exceeds limit")
            return json.loads(payload)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise


def registry_preflight(version):
    existing = registry("crates/" + POLICY["package"])
    require(existing and existing["crate"]["name"] == POLICY["package"],
            "first publication requires a separate ownership/bootstrap review")
    require((existing["crate"].get("repository") or "").lower() == POLICY["repository"].lower(),
            "registry repository metadata mismatch; check ownership")
    require(registry(f"crates/{POLICY['package']}/{version}") is None,
            "version already exists: inspect prior upload; never overwrite or blindly retry")


def validate_ci(data, head):
    runs = data.get("workflow_runs", [])
    require(type(data.get("total_count")) is int and data["total_count"] == len(runs) and runs,
            "complete matching CI history required")
    newest = max(runs, key=lambda item: item["id"])
    require(newest.get("head_sha") == head and newest.get("event") == "push"
            and newest.get("head_branch") == "main"
            and newest.get("repository", {}).get("full_name") == POLICY["github"]
            and newest.get("path") == ".github/workflows/ci.yml"
            and newest.get("status") == "completed" and newest.get("conclusion") == "success",
            "latest main CI for this exact commit must pass")


def guard(package):
    from check_release_environment import api
    head = run("git", "rev-parse", "HEAD")
    publication_context(os.environ, head)
    version_for_event(package, os.environ)
    require(not run("git", "status", "--porcelain"), "clean committed source required")
    current = api("repos/" + POLICY["github"] + "/commits/main")
    require(current["sha"] == head, "main moved: qualify the new source in a new run")
    validate_ci(api(f"repos/{POLICY['github']}/actions/workflows/ci.yml/runs"
                    f"?head_sha={head}&event=push&branch=main&per_page=100"), head)
    registry_preflight(package["version"])


def inspect_archive(path, package, head):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size < 10_000_000,
            "missing, linked or oversized crate")
    prefix = f"{package['name']}-{package['version']}"
    seen, total = set(), 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            require(len(parts) >= 2 and parts[0] == prefix and ".." not in parts
                    and not member.name.startswith("/") and member.isfile(), "unsafe archive entry")
            relative = "/".join(parts[1:])
            require(relative not in seen, "duplicate archive entry")
            seen.add(relative)
            total += member.size
            require(len(seen) <= 1000 and total <= 50_000_000, "archive exceeds review limits")
            require(relative in POLICY["files"]
                    or relative.startswith("src/") and relative.endswith(".rs"),
                    "unexpected file in source package: " + relative)
            if relative == ".cargo_vcs_info.json":
                info = json.load(archive.extractfile(member))
                require(info["git"]["sha1"] == head and not info["git"].get("dirty", False)
                        and info["path_in_vcs"] == str(Path(POLICY["manifest"]).parent),
                        "crate does not identify the clean checked-out source")
    require(set(POLICY["required_files"]) <= seen, "required source/license files missing")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "archive", "guard", "publish"))
    args = parser.parse_args()
    package, target = metadata()
    version = version_for_event(package, os.environ)
    path = target / "package" / f"{package['name']}-{version}.crate"
    if args.command == "plan":
        print(json.dumps({"package": package["name"], "version": version}))
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                output.write(f"package={package['name']}\nversion={version}\n")
    elif args.command == "guard":
        guard(package)
    else:
        digest = inspect_archive(path, package, run("git", "rev-parse", "HEAD"))
        if args.command == "archive":
            print(digest)
            if os.environ.get("GITHUB_OUTPUT"):
                with open(os.environ["GITHUB_OUTPUT"], "a") as output:
                    output.write(f"sha256={digest}\n")
            return
        require(digest == os.environ.get("TESTED_CRATE_SHA256"), "tested archive hash mismatch")
        guard(package)
        require(os.environ.get("CARGO_REGISTRY_TOKEN"), "short-lived publication token required")
        # No --no-verify, --allow-dirty, wildcard, workspace publication or retries.
        subprocess.run(("cargo", "publish", "--locked", "--registry", "crates-io",
                        "--package", package["name"]), cwd=ROOT, check=True)
        require(inspect_archive(path, package, run("git", "rev-parse", "HEAD")) == digest,
                "Cargo changed the tested package during publication; investigate the upload")
        for _ in range(12):
            published = registry(f"crates/{package['name']}/{version}")
            if published:
                require(published["version"].get("checksum") == digest
                        and published["version"].get("num") == version
                        and published["version"].get("yanked") is False,
                        "published checksum/version/yank state mismatch")
                print(f"Verified crates.io {package['name']} {version}: {digest}")
                return
            time.sleep(5)
        raise ValueError("upload may have succeeded; inspect registry before any new attempt")


if __name__ == "__main__":
    main()
