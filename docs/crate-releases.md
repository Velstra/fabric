# Publishing the public library

Only **velstra-proto** is selected in `crate-release.toml`. This is a source-library
release, not appliance or daemon certification. Sentinel remains image-only;
private Enterprise sources and internal workspace members are not published.
The remaining dataplane crates still use Git-only dependencies; do not substitute registry versions or publish the workspace to work around this.

## One-time owner setup

For the existing crate on crates.io, configure Trusted Publishing:
repository `Velstra/fabric`, workflow `crates-release.yml`, environment
`crates-io`. Confirm actual crate ownership; repository metadata alone is not
proof of ownership. No long-lived crates.io token is stored in GitHub.

Create the public repository's `crates-io` environment with independent required
reviewers, prevent self-review, no administrator bypass, and exactly the
deployment branch `main`. The workflow verifies the rules and actual approval.
Do not weaken the gate if the environment is not configured. A project with one
maintainer uses [single-operator mode](#single-operator-mode) instead.

## Single-operator mode

The default is a two-person rule: `crates-io` must forbid self-review, and the
approval must come from someone who did not start the run. A project with one
maintainer can never meet it. Setting the repository variable
`RELEASE_SINGLE_OPERATOR` to exactly `true` replaces it with this rule; any
other value, or no variable, keeps the two-person rule.

The `crates-io` environment then needs:

- exactly one required-reviewers rule naming at least one reviewer
  (self-review may be allowed);
- administrator bypass disabled;
- a wait timer of at least 30 minutes
  (`SINGLE_OPERATOR_MIN_WAIT_MINUTES` in `scripts/check_release_environment.py`);
- the same branch policy as above: exactly the branch `main`, no tags.

The publish job still requires a real `approved` review of the current run in
`crates-io` by a GitHub `User` account. The maintainer may approve their own
run, but the job having started is never taken as an approval. The environment
check writes "Release approvals: single-operator mode (one maintainer, wait
timer ≥ 30 min)." as a run annotation.

What it protects against: a stolen workflow-scoped or repository-write token
cannot publish on its own. It cannot approve a deployment, and the wait timer
holds the publish job for at least 30 minutes, which gives the maintainer time
to reject the run or cancel it. Bypass is off, so an administrator cannot start
the waiting job past the review and the timer.

What it does not protect against: there is no second person. A compromised
maintainer account or a token with the maintainer's approval rights can approve
its own run; the wait timer only delays it, and only helps if the maintainer
notices the pending deployment. A repository administrator can also edit the
environment or the variable. The publish job rechecks the environment once it
starts, so a timer removed while the job waits fails that job, but a change
reverted before the job starts is not seen. Watch deployment-review
notifications while single-operator mode is on.

To switch back, once a second maintainer exists, delete the variable
(`gh variable delete RELEASE_SINGLE_OPERATOR`) or set it to `false`, then
enable self-review prevention on `crates-io` and add the independent reviewer.
The next run enforces the two-person rule again; the wait timer may stay.

## Test, then publish

Commit the intended version, source and lockfile, merge after CI, then run:

```sh
gh workflow run crates-release.yml --repo Velstra/fabric --ref main -f version=VERSION -F publish=false
```

Replace VERSION with the crate's exact Cargo version, without `v`. Once the
candidate is reviewed, dispatch with `-F publish=true` and independently approve
the job (or, in [single-operator mode](#single-operator-mode), approve it yourself). Pull requests, main pushes and tags only test; they never publish.
The separate image release and this source-library release do not share a
version counter or signing key. Local `cargo release` remains tag/version-only.

Every run tests all library features and executes a real, locked
`cargo publish --dry-run`, including the extracted package build. Package
contents are allowlisted, size-bounded and tied to the clean commit. Publication
requires the latest main CI for the exact still-current commit, a first-attempt
manual request and an unchanged rebuilt archive. It publishes only the named
crate to crates.io and checks the registry's version and SHA256 afterward.

Existing versions are rejected, not overwritten or silently treated as success.
An upload error or timeout can occur **after** the registry accepts the package:
inspect the registry and retained run/hash before deciding what to do next.
The workflow never automatically retries publication, yanks versions, changes
owners, bootstraps new names, or claims atomic publication across services.

Source commits, dependencies and build scripts remain part of the trusted
publication runner. Trusted Publishing removes stored credentials; it does not
make compromised release source safe. Registry authentication/upload cannot be
fully validated by dry-runs; the first approved real release is still required.

References: [Cargo publication](https://doc.rust-lang.org/cargo/commands/cargo-publish.html),
[Trusted Publishing action](https://github.com/rust-lang/crates-io-auth-action).
