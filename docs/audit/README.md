# Review source inventory

The dated SHA-256 inventory identifies selected first-party and vendored Rust
sources and manifests in the submitted working tree, plus the workspace lockfile.
It excludes build outputs, wallet files and live databases. It is not proof of
security or a complete dependency inventory. Pin the reviewed commit before release.
