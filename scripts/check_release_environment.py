#!/usr/bin/env python3
"""Require an actually protected release environment, not just a YAML name."""
import argparse
import json
import os
import re
import subprocess
from urllib.parse import quote

# Single-operator mode: the shortest wait_timer (minutes) an environment may
# carry, so a run started with a stolen token cannot release before the owner
# can reject it.
SINGLE_OPERATOR_MIN_WAIT_MINUTES = 30


def single_operator_enabled():
    """Opt-in only: the repository variable must be exactly `true`."""
    return os.environ.get("RELEASE_SINGLE_OPERATOR") == "true"


def approvals_statement():
    """The line a release made in single-operator mode carries; None otherwise."""
    if not single_operator_enabled():
        return None
    return ("Release approvals: single-operator mode "
            f"(one maintainer, wait timer \u2265 {SINGLE_OPERATOR_MIN_WAIT_MINUTES} min).")


def rules_of(environment, kind):
    return [r for r in environment.get("protection_rules") or [] if r.get("type") == kind]


def validate_single_operator(environment):
    reviewers = rules_of(environment, "required_reviewers")
    if (len(reviewers) != 1 or not reviewers[0].get("reviewers")
            or environment.get("can_admins_bypass") is True):
        raise ValueError("single-operator mode requires one reviewer rule with a reviewer and no admin bypass")
    timers = rules_of(environment, "wait_timer")
    if (len(timers) != 1 or type(timers[0].get("wait_timer")) is not int
            or timers[0]["wait_timer"] < SINGLE_OPERATOR_MIN_WAIT_MINUTES):
        raise ValueError("single-operator mode requires a wait timer of at least "
                         f"{SINGLE_OPERATOR_MIN_WAIT_MINUTES} minutes")


def validate(environment, branches, single_operator=False):
    policy = environment.get("deployment_branch_policy") or {}
    if single_operator:
        validate_single_operator(environment)
    else:
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


def approval(environment, history, actors, single_operator=False):
    if not isinstance(history, list):
        raise ValueError("approval history unavailable")
    relevant = [r for r in history if any(e.get("id") == environment.get("id")
                for e in r.get("environments", []))]
    if single_operator:
        # The one maintainer may approve their own run, but the approval must
        # exist: a job that merely started (bypass, no rule) is not one.
        if (not relevant or any(r.get("state") != "approved" for r in relevant)
                or not any(r.get("user", {}).get("type") == "User" and r["user"].get("login")
                           for r in relevant)):
            raise ValueError("an actual human approval for this run is required")
        return
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
    single = single_operator_enabled()
    validate(environment, api(root + "/deployment-branch-policies?per_page=100"), single)
    if args.approved:
        if os.environ["GITHUB_RUN_ATTEMPT"] != "1":
            raise ValueError("start a new run instead of reusing an approval")
        approval(environment, api(f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/runs/"
                                  f"{os.environ['GITHUB_RUN_ID']}/approvals"),
                 {os.environ.get("GITHUB_ACTOR"), os.environ.get("GITHUB_TRIGGERING_ACTOR")}, single)
    if single:
        print(f"::notice title={args.environment}::{approvals_statement()}")
