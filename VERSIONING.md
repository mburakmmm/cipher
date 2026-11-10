# Versioning Policy — Cipher

Cipher adheres strictly to [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** (`vX.0.0`): Incompatible API changes, breaking cryptographic contract changes, or tightened default validation profiles that require caller modification.
- **MINOR** (`v0.X.0` or `v1.X.0`): Backward-compatible new features, newly supported cryptographic algorithms (e.g., PS256, ES256), or key management enhancements.
- **PATCH** (`v0.0.X` or `v1.0.X`): Backward-compatible bug fixes, security hardening, performance improvements, and documentation updates.

### Pre-v1.0.0 Notice

During the initial `v0.x.y` development series, the public API is stabilizing. Any breaking changes between minor versions will be prominently documented in `CHANGELOG.md` alongside migration instructions.

### Security Releases

Security advisories and patches are prioritized and released as immediate patch versions. A security fix that strictly tightens validation to eliminate an attack vector is considered a patch if it conforms to normative RFC specifications.
