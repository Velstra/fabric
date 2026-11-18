# Release qualification

Choose a release image by tag or exact commit. The CI pipeline publishes controller, agent and CNI containers only from deliberate `v*` tags that pass verification.

| Event | Result |
|---|---|
| Pull request or main-branch integration | Host tests, build and kernel verifier checks. No container release. |
| Qualified version tag | Host, build, verifier and dataplane jobs must succeed before publication. Container images receive version and full-commit tags. |
| GitHub release | Requires successful image publication and release notes for that version. |

For a checkout you intend to deploy, compare `git rev-parse HEAD` to the full-commit tag and read its [release notes](https://github.com/Velstra/fabric/releases). The [workflow](https://github.com/Velstra/fabric/blob/main/.github/workflows/ci.yml) defines the exact gates. Sentinel's appliance-level signing and upgrade tests have their own qualification process.
