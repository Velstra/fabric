# Integration and publication

Merging a pull request into `main` runs verification; it does not publish
containers or a GitHub release. Integration is not appliance certification.

A deliberate `v*` tag runs host checks, the full build, the real kernel verifier
and the datapath traffic suite. Both container publication and GitHub release
creation require these jobs to succeed for that tag. Release creation also
requires successful container publication and nonempty version release notes.
Images receive the exact version and full commit SHA, never an automatic
`latest` promotion from `main`.

No release tag should be created until its applicable qualification is complete.
Sentinel image, HA rolling-upgrade and signed update-channel certification remain
separate requirements; a green Fabric workflow is not that certificate.
