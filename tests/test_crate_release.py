import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import crate_release as release
import check_release_environment as protection


MAIN_ONLY = {"total_count": 1, "branch_policies": [{"type": "branch", "name": "main"}]}


def single_operator_environment(wait_timer=30, reviewers=(), prevent_self_review=False):
    """GitHub's environment shape: one reviewer, a wait timer, custom branches."""
    rules = [{"id": 2, "node_id": "R", "type": "required_reviewers", "prevent_self_review": prevent_self_review,
              "reviewers": list(reviewers) if reviewers != () else
              [{"type": "User", "reviewer": {"login": "owner", "id": 1, "type": "User"}}]},
             {"id": 3, "node_id": "B", "type": "branch_policy"}]
    if wait_timer is not None:
        rules.insert(0, {"id": 1, "node_id": "W", "type": "wait_timer", "wait_timer": wait_timer})
    return {"id": 7, "name": "crates-io", "protection_rules": rules, "can_admins_bypass": False,
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}


class ReleaseGuards(unittest.TestCase):
    def setUp(self):
        self.head = "a" * 40
        self.package = {"name": release.POLICY["package"], "version": "1.2.3",
                        "repository": release.POLICY["repository"],
                        "license": release.POLICY["license"], "publish": ["crates-io"],
                        "targets": [{"kind": ["lib"]}], "dependencies": []}
        self.context = {"GITHUB_REPOSITORY": release.POLICY["github"],
                        "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                        "PUBLISH_REQUESTED": "true", "GITHUB_RUN_ATTEMPT": "1",
                        "GITHUB_SHA": self.head, "REQUESTED_VERSION": "1.2.3"}

    def test_selected_library(self):
        release.validate_package(self.package)

    def test_private_wrong_name_license_repository_binary_refused(self):
        for field, value in (("publish", False), ("name", "enterprise"),
                             ("repository", "https://example.invalid"),
                             ("license", "proprietary"), ("targets", [{"kind": ["bin"]}])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                release.validate_package(dict(self.package, **{field: value}))

    def test_git_path_and_private_registry_refused(self):
        for dep in ({"source": "git+https://example.invalid"}, {"path": "../private"},
                    {"source": "registry+https://private.invalid"}):
            with self.subTest(dep=dep), self.assertRaises(ValueError):
                release.validate_package(dict(self.package, dependencies=[dep]))

    def test_public_registry_dependency(self):
        release.validate_package(dict(self.package, dependencies=[
            {"source": "registry+https://github.com/rust-lang/crates.io-index"}]))

    def test_exact_version(self):
        self.assertEqual(release.version_for_event(self.package, self.context), "1.2.3")
        for version in ("v1.2.3", "1.2.4", ""):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release.version_for_event(self.package, dict(self.context, REQUESTED_VERSION=version))
        with self.assertRaises(ValueError):
            release.version_for_event(self.package, {"GITHUB_REF": "refs/tags/v1.2.4"})

    def test_manual_main_first_attempt_only(self):
        release.publication_context(self.context, self.head)
        for key, value in (("GITHUB_REPOSITORY", "attacker/fork"),
                           ("GITHUB_EVENT_NAME", "push"), ("GITHUB_REF", "refs/tags/v1.2.3"),
                           ("PUBLISH_REQUESTED", "false"), ("GITHUB_RUN_ATTEMPT", "2"),
                           ("GITHUB_SHA", "b" * 40)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                release.publication_context(dict(self.context, **{key: value}), self.head)

    def test_latest_exact_source_ci(self):
        good = {"id": 1, "head_sha": self.head, "event": "push", "head_branch": "main",
                "repository": {"full_name": release.POLICY["github"]},
                "path": ".github/workflows/ci.yml", "status": "completed", "conclusion": "success"}
        release.validate_ci({"total_count": 1, "workflow_runs": [good]}, self.head)
        for changed in ({"head_sha": "b"*40}, {"event": "pull_request"}, {"status": "in_progress"},
                        {"conclusion": "failure"}, {"path": ".github/workflows/other.yml"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                release.validate_ci({"total_count": 2, "workflow_runs":
                                     [good, dict(good, id=2, **changed)]}, self.head)
        with self.assertRaises(ValueError):
            release.validate_ci({"total_count": 2, "workflow_runs": [good]}, self.head)

    def test_registry_no_create_overwrite_or_identity_swap(self):
        crate = {"crate": {"name": release.POLICY["package"],
                           "repository": release.POLICY["repository"]}}
        with patch.object(release, "registry", side_effect=[crate, None]):
            release.registry_preflight("1.2.3")
        for values in ([None], [crate, {"version": {}}],
                       [{"crate": dict(crate["crate"], repository="https://other.invalid")}]):
            with patch.object(release, "registry", side_effect=values), self.assertRaises(ValueError):
                release.registry_preflight("1.2.3")

    def make_archive(self, path, extra=None, sha=None, dirty=False):
        files = {name: b"source" for name in release.POLICY["required_files"]}
        files[".cargo_vcs_info.json"] = json.dumps({
            "git": {"sha1": sha or self.head, "dirty": dirty},
            "path_in_vcs": str(Path(release.POLICY["manifest"]).parent)}).encode()
        files.update(extra or {})
        with tarfile.open(path, "w:gz") as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(f"{self.package['name']}-1.2.3/{name}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def test_real_archive_identity_and_private_file_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.crate"
            self.make_archive(path)
            self.assertEqual(len(release.inspect_archive(path, self.package, self.head)), 64)
            for kwargs in ({"extra": {"db.key": b"secret"}}, {"extra": {"../escape": b"x"}},
                           {"sha": "b"*40}, {"dirty": True}):
                self.make_archive(path, **kwargs)
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    release.inspect_archive(path, self.package, self.head)

    def test_publish_upload_is_scoped_and_hash_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            path = target / "package" / "tmp-registry" / f"{self.package['name']}-1.2.3.crate"
            path.parent.mkdir(parents=True)
            self.make_archive(path)
            digest = release.inspect_archive(path, self.package, self.head)
            for expected, remote_digest, succeeds in (
                (digest, digest, True), ("0"*64, digest, False), (digest, "0"*64, False)
            ):
                env = dict(self.context, TESTED_CRATE_SHA256=expected, CARGO_REGISTRY_TOKEN="fixture-only")
                with self.subTest(expected=expected, remote=remote_digest), \
                     patch.dict(release.os.environ, env, clear=True), \
                     patch.object(sys, "argv", ["crate_release.py", "publish"]), \
                     patch.object(release, "metadata", return_value=(self.package, target)), \
                     patch.object(release, "run", return_value=self.head), \
                     patch.object(release, "guard"), \
                     patch.object(sys, "stdout", new_callable=io.StringIO), \
                     patch.object(release.subprocess, "run") as upload, \
                     patch.object(release, "registry", return_value={"version": {
                         "num": "1.2.3", "checksum": remote_digest, "yanked": False}}):
                    if succeeds:
                        release.main()
                    else:
                        with self.assertRaises(ValueError):
                            release.main()
                    if expected != digest:
                        upload.assert_not_called()
                    else:
                        upload.assert_called_once_with(
                            ("cargo", "publish", "--locked", "--registry", "crates-io",
                             "--package", self.package["name"]), cwd=release.ROOT, check=True)

    def test_actual_environment_protection(self):
        environment = {"id": 7, "deployment_branch_policy":
                       {"protected_branches": False, "custom_branch_policies": True},
                       "protection_rules": [{"type": "required_reviewers", "reviewers": [{"id": 9}],
                                             "prevent_self_review": True}]}
        branches = {"total_count": 1, "branch_policies": [{"type": "branch", "name": "main"}]}
        protection.validate(environment, branches)
        for update in ({"protection_rules": []}, {"can_admins_bypass": True}):
            with self.assertRaises(ValueError):
                protection.validate(dict(environment, **update), branches)
        history = [{"state": "approved", "environments": [{"id": 7}],
                    "user": {"type": "User", "login": "reviewer"}}]
        protection.approval(environment, history, {"author"})
        for actors in ({"reviewer"},):
            with self.assertRaises(ValueError):
                protection.approval(environment, history, actors)
        with self.assertRaises(ValueError):
            protection.validate(environment, {"total_count": 1, "branch_policies":
                                               [{"type": "tag", "name": "v*"}]})

    def test_two_person_mode_is_unchanged_by_single_operator_settings(self):
        # A single-operator environment (self-review allowed) never satisfies the
        # default two-person rule, and the default still refuses self-approval.
        with self.assertRaisesRegex(ValueError, "prevent-self-review"):
            protection.validate(single_operator_environment(), MAIN_ONLY)
        mine = {"environments": [{"id": 7}], "state": "approved", "user": {"type": "User", "login": "owner"}}
        with self.assertRaisesRegex(ValueError, "independent"):
            protection.approval({"id": 7}, [mine], {"owner"})

    def test_single_operator_mode_is_opt_in_by_exact_value(self):
        for value, expected in (("true", True), ("True", False), ("1", False), ("yes", False),
                                ("", False), ("false", False), (" true", False)):
            with self.subTest(value=value), patch.dict(os.environ, {"RELEASE_SINGLE_OPERATOR": value}):
                self.assertIs(protection.single_operator_enabled(), expected)
        with patch.dict(os.environ):
            os.environ.pop("RELEASE_SINGLE_OPERATOR", None)
            self.assertIs(protection.single_operator_enabled(), False)

    def test_single_operator_mode_accepts_reviewer_wait_timer_and_no_bypass(self):
        self.assertEqual(protection.SINGLE_OPERATOR_MIN_WAIT_MINUTES, 30)
        for environment in (single_operator_environment(),
                            single_operator_environment(prevent_self_review=True),
                            single_operator_environment(wait_timer=43200)):
            with self.subTest(environment=environment):
                protection.validate(environment, MAIN_ONLY, single_operator=True)

    def test_single_operator_mode_refuses_weakened_environments(self):
        reviewers = single_operator_environment()["protection_rules"][0]
        cases = {
            "missing wait timer": single_operator_environment(wait_timer=None),
            "short wait timer": single_operator_environment(wait_timer=29),
            "zero wait timer": single_operator_environment(wait_timer=0),
            "boolean wait timer": single_operator_environment(wait_timer=True),
            "string wait timer": single_operator_environment(wait_timer="30"),
            "two wait timers": single_operator_environment() | {"protection_rules":
                single_operator_environment()["protection_rules"] + [{"type": "wait_timer", "wait_timer": 30}]},
            "admin bypass": single_operator_environment() | {"can_admins_bypass": True},
            "no reviewers": single_operator_environment(reviewers=[]),
            "no reviewer rule": single_operator_environment() | {"protection_rules": [
                r for r in single_operator_environment()["protection_rules"] if r["type"] != "required_reviewers"]},
            "two reviewer rules": single_operator_environment() | {"protection_rules":
                single_operator_environment()["protection_rules"] + [reviewers]},
            "no protection": single_operator_environment() | {"protection_rules": []},
        }
        for name, environment in cases.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                protection.validate(environment, MAIN_ONLY, single_operator=True)
        # The branch rule is exactly that of the two-person mode: main, and nothing else.
        for policy in ({"branch_policies": [{"type": "branch", "name": "*"}]},
                       MAIN_ONLY | {"total_count": 101},
                       {"total_count": 1, "branch_policies": [{"type": "tag", "name": "v*"}]},
                       {"total_count": 2, "branch_policies": [{"type": "branch", "name": "main"},
                                                              {"type": "tag", "name": "v*"}]}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                protection.validate(single_operator_environment(), policy, single_operator=True)
        with self.assertRaises(ValueError):
            protection.validate(single_operator_environment() | {"deployment_branch_policy": None},
                                MAIN_ONLY, single_operator=True)

    def test_single_operator_approval_may_be_self_but_must_exist(self):
        environment = {"id": 7}
        mine = {"environments": [{"id": 7}], "state": "approved", "user": {"type": "User", "login": "owner"}}
        protection.approval(environment, [mine], {"owner"}, single_operator=True)
        protection.approval(environment, [mine | {"user": {"type": "User", "login": "other"}}], {"owner"},
                            single_operator=True)
        for history in (None, [], [mine | {"state": "rejected"}], [mine | {"state": "pending"}],
                        [mine, mine | {"state": "rejected"}],
                        [mine | {"environments": [{"id": 8}]}], [mine | {"environments": []}],
                        [mine | {"user": {"type": "Bot", "login": "owner"}}],
                        [mine | {"user": {"type": "Organization", "login": "owner"}}],
                        [mine | {"user": {"type": "User"}}], [mine | {"user": {}}], [{"environments": [{"id": 7}]}]):
            with self.subTest(history=history), self.assertRaises(ValueError):
                protection.approval(environment, history, {"owner"}, single_operator=True)

    def test_single_operator_runs_say_so(self):
        with patch.dict(os.environ, {"RELEASE_SINGLE_OPERATOR": "true"}):
            statement = protection.approvals_statement()
        self.assertEqual(statement, "Release approvals: single-operator mode "
                                    "(one maintainer, wait timer \u2265 30 min).")
        with patch.dict(os.environ, {"RELEASE_SINGLE_OPERATOR": "false"}):
            self.assertIsNone(protection.approvals_statement())

    def test_pagination_is_not_silent_truncation(self):
        self.assertEqual(protection.response_document("HTTP/2 200 OK\n\n{}"), {})
        with self.assertRaises(ValueError):
            protection.response_document("HTTP/2 200 OK\nLink: next\n\n{}")

    def test_workflow_does_not_publish_workspace_or_use_static_secrets(self):
        workflow = (ROOT / ".github/workflows/crates-release.yml").read_text()
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("--workspace", workflow)
        self.assertNotIn("--allow-dirty", workflow)
        self.assertNotIn("--no-verify", workflow)
        self.assertIn("environment: crates-io", workflow)
        self.assertIn("--approved", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("inputs.publish", workflow)
        self.assertIn("needs: check", workflow)
        self.assertIn("RELEASE_SINGLE_OPERATOR: ${{ vars.RELEASE_SINGLE_OPERATOR || 'false' }}", workflow)


if __name__ == "__main__":
    unittest.main()
