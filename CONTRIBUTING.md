# Contributing to keymap

## Ground rules

- **Never commit a real key.** Tests and examples use obviously fake
  values. If you need a new provider pattern, craft a fixture value
  that matches the pattern but contains no real key material — and
  check that `python -m keymap` on the repo reports nothing real.
  Note: GitHub push protection blocks some live-key-looking literals
  (e.g. a contiguous `sk_live_…` value) even when fake, so build such
  fixture values from parts in test code instead of writing them out.
- **keymap never prints key material.** Any new output path must show
  prefixes + fingerprints only. Add a test asserting the full fixture
  value does not appear in the report.
- **Read-only stays read-only.** No network, no writes, no telemetry.

## Development

```bash
python -m unittest discover -s tests
sh examples/run-demo.sh
```

## Adding a provider pattern

1. Add the regex + public prefix to `keymap/patterns.py`, plus its
   revoke URL in `ROTATION_URLS`.
2. Add a fixture + test in `tests/test_keymap.py`.
3. Update the provider list in `README.md`.
