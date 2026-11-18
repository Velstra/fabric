#!/usr/bin/env python3
"""Require an actually protected release environment, not just a YAML name."""
import argparse
import json
import os
import re
import subprocess
from urllib.parse import quote


def validate(environment, branches):
    policy = environment.get("deployment_branch_policy") or {}
    rules = [r for r in environment.get("protection_rules", []) if r.get("type") == "required_reviewers"]
    if (len(rules) != 1 or not rules[0].get("reviewers")
            or rules[0].get("prevent_self_review") is not True
            or environment.get("can_admins_bypass") is True):
        raise ValueError("required reviewers and prevent-self-review must be enabled")
    entries = branches.get("branch_policies", [])
    if (type(branches.get("total_count")) is not int
            or branches["total_count"] != len(entries) or len(entries) != 1):
        raise ValueError("complete exact release branch policies required")
    names = {(b.get("type"), b.get("name")) for b in entries}
    if (policy != {"protected_branches": False, "custom_branch_policies": True}
            or not names or names != {("branch", "main")}
            or ("branch", "main") not in names):
        raise ValueError("only main may enter the release environment")


def approval(environment, history, actors):
    if not isinstance(history, list):
        raise ValueError("approval history unavailable")
    relevant = [r for r in history if any(e.get("id") == environment.get("id")
                for e in r.get("environments", []))]
    if (not relevant or any(r.get("state") != "approved" for r in relevant)
            or not any(r.get("user", {}).get("type") == "User"
                       and r["user"].get("login") and r["user"]["login"] not in actors for r in relevant)):
        raise ValueError("an actual independent human approval for this run is required")


def response_document(raw):
    parts = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    if (len(parts) != 2 or not parts[0].startswith("HTTP/")
            or any(line.lower().startswith("link:") for line in parts[0].splitlines())):
        raise ValueError("incomplete or paginated protection response")
    return json.loads(parts[1])


def api(path):
    return response_document(subprocess.check_output(["gh", "api", "--include", path], text=True, timeout=30))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment")
    parser.add_argument("--approved", action="store_true")
    args = parser.parse_args()
    root = f"repos/{os.environ['GITHUB_REPOSITORY']}/environments/{quote(args.environment, safe='')}"
    environment = api(root)
    if environment.get("name") != args.environment or type(environment.get("id")) is not int:
        raise ValueError("environment identity mismatch")
    validate(environment, api(root + "/deployment-branch-policies?per_page=100"))
    if args.approved:
        if os.environ["GITHUB_RUN_ATTEMPT"] != "1":
            raise ValueError("start a new run instead of reusing an approval")
        approval(environment, api(f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
                                  f"{os.environ['GITHUB_RUN_ID']}/approvals"),
                 {os.environ.get("GITHUB_ACTOR"), os.environ.get("GITHUB_TRIGGERING_ACTOR")})
