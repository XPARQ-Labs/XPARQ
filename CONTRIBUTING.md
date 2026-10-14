# Contributing to XPARQ

Thanks for taking the time to improve XPARQ. Contributions can include bug
reports, documentation, code, examples, and reviews.

## Before you start

- Check the existing documentation and issues to see whether the problem or
  proposed change is already being discussed.
- For a large change, open an issue or discussion first so the scope and design
  can be aligned with the maintainers.
- For consensus, cryptography, transaction encoding, monetary rules, or storage
  format changes, explain compatibility and security implications in the
  proposal. These changes can affect network agreement or require fresh local
  chain data.
- Never include private keys, wallet files, mnemonics, or real signing material
  in issues, pull requests, logs, or test fixtures.

## Set up the project

Install Git, Rust, and Cargo. The repository pins the development toolchain in
`rust-toolchain.toml` (currently Rust 1.99.0, with rustfmt and Clippy). Rustup
can install the selected toolchain automatically when you run a Cargo command.

Fork the repository on GitHub and clone your fork:

```bash
git clone https://github.com/<YOUR-USERNAME>/XPARQ.git
cd XPARQ
git remote add upstream https://github.com/XPARQ-Labs/XPARQ.git
```

Create a branch for your change:

```bash
git switch -c <short-description>
```

## Make and check a change

Keep each change focused. Update relevant documentation and examples when
behavior or commands change. Do not reformat unrelated files or modify vendored
dependencies unless the contribution specifically requires it.

Run checks relevant to your changes. For Rust changes, the usual workspace
checks are:

```bash
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked
cargo test --workspace --locked
```

The GitHub Actions workflow builds and tests the locked workspace for pull
requests targeting `main`. Some integration or lifecycle checks may require
additional setup; describe any checks you could not run and why.

For dependency changes, also review `docs/TOOLING.md` and run the applicable
`cargo deny` checks when available. Do not update `Cargo.lock` as a side effect
unless dependency selection intentionally changed.

## Submit a pull request

Push your branch to your fork and open a pull request against the `main` branch
of `XPARQ-Labs/XPARQ`:

```bash
git push -u origin <short-description>
```

In the pull request description:

- Explain the problem and the change.
- Link related issues or discussions.
- List the checks you ran and their results.
- Call out compatibility, consensus, storage, or security implications where
  applicable.
- Include screenshots or sample output for user-visible changes when useful.

Keep the PR focused and respond to review feedback. Maintainers may ask for
changes, clarification, or additional validation before merging.

## Report bugs and security issues

For ordinary bugs, open a GitHub issue with the affected version or commit,
steps to reproduce, expected behavior, actual behavior, and relevant logs with
secrets removed.

For suspected vulnerabilities, follow [`SECURITY.md`](SECURITY.md). Do not post
exploit details publicly before maintainers have had an opportunity to
investigate. The security policy describes how to proceed if the private
vulnerability-reporting channel is unavailable.

## License

By submitting a contribution, you agree that it is provided under the
repository's [MIT License](LICENSE), consistent with the project license.
