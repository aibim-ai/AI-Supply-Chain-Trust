## Summary

Describe the user-visible outcome and the evidence supporting it.

## Verification

- [ ] Focused tests pass
- [ ] `cargo fmt --all -- --check` passes for Rust changes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes for Rust changes
- [ ] Frontend lint, tests, and build pass for frontend changes
- [ ] No credentials, webhook URLs, private data, or generated local artifacts are included
- [ ] Documentation and migration compatibility are updated where needed

## Security and data impact

Describe changes to trust boundaries, public APIs, persisted data, provider calls,
and secret handling. Write “none” only after checking each category.
