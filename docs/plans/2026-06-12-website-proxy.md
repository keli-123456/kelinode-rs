# Website proxy implementation plan

## Goal

Add a first-party website reverse proxy beside the existing subscription reverse proxy. Both features share the existing HTTPS listener and ZeroSSL certificate, so a machine can expose subscription URLs and the ordering website through the same IP and port without duplicating TLS state.

## Scope

- Extend the Rust agent config with website proxy profiles.
- Preserve `/sub/{site}/{token}` subscription routing priority.
- Add direct root website proxying and optional path-prefixed site routing.
- Forward normal website methods and request bodies with bounded reads.
- Rewrite redirect and cookie headers enough for path-prefixed proxying.
- Extend keliboard machine config generation so website proxy can be enabled independently while reusing the subscription proxy certificate.
- Add focused Rust and PHP tests where local runtimes allow.

## Stability rules

- Keep the feature closed to configured upstreams only; do not build an arbitrary open proxy.
- Keep subscription proxy behavior backward-compatible.
- Bound request and response bodies to avoid unbounded memory growth.
- Reuse existing certificate files and reload drift checks.
