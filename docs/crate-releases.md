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
Do not weaken the gate if the environment is not configured.

## Test, then publish

Commit the intended version, source and lockfile, merge after CI, then run:

```sh
gh workflow run crates-release.yml --repo Velstra/fabric --ref main -f version=VERSION -F publish=false
```

Replace VERSION with the crate's exact Cargo version, without `v`. Once the
candidate is reviewed, dispatch with `-F publish=true` and independently approve
the job. Pull requests, main pushes and tags only test; they never publish.
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
