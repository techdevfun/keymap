# keymap — where do your API keys actually live?

In October 2026, a breach at an agent-tool vendor exposed provider API
keys (OpenAI, Anthropic, Google) stored in its console workspaces.
Developers affected by it faced the same awkward question: **which keys
do I have, where are they stored, and which ones do I need to rotate?**

Most of us can't answer that in under a minute. A provider key gets
pasted into a Claude Code config, then a Codex config, then an `.env`
file, then shell history — and every copy is another place it can leak
from, another line on the bill if it's abused.

**keymap** answers the question locally, in seconds:

```bash
python -m keymap
```

It scans the config files your agent tools, CLIs and shells actually
read — `~/.claude.json`, `~/.codex/config.toml`, `~/.env`, shell rc
files and history, `~/.aws/credentials`, and friends — and reports
where each provider key sits, whether the same key is sprawled across
files, whether its file is world-readable, whether it landed in shell
history, and whether it's one careless `git add .` away from a commit.
It finishes with a rotation checklist: the exact revoke pages for every
provider it found.

## What it never does

- **Never prints key material.** Reports show only the public prefix
  (`sk-ant-…`) plus a SHA-256 fingerprint prefix (`…776a5e869d89`), so
  you can recognise the *same* key across files without seeing it.
- **Never sends anything anywhere.** No network, no telemetry, no
  uploads. It only reads files on your machine.
- **Never writes.** Read-only by design. It tells you what to fix; you
  fix it.

## Demo (all values fake)

`examples/demo-home/` is a fake home directory with the same Anthropic
key in two files, an OpenAI key in `.env` *and* shell history, a GitHub
token in `~/.claude.json`, and a world-readable `.env`. Run:

```bash
sh examples/run-demo.sh
```

Real output (see `examples/expected-output.txt`):

```
keymap — API key footprint report
Files scanned: 5  Skipped: 0

Keys found: 5 across 5 file(s) — providers: openai, github, anthropic

Occurrences (prefix + fingerprint only — no key material):
  .claude.json:1  github  (unknown)  ghp_…685d57433a9e  [GitHub classic personal access token]
  .codex/config.toml:5  anthropic  api_key  sk-ant-…776a5e869d89  [Anthropic API key]
  .config/app.json:1  anthropic  (unknown)  sk-ant-…776a5e869d89  [Anthropic API key]
  .env:3  openai  OPENAI_API_KEY  sk-proj-…29289fad0238  [OpenAI project API key]
  .zsh_history:1  openai  OPENAI_API_KEY  sk-proj-…29289fad0238  [OpenAI project API key]

Findings:
  [HIGH] world-readable — .env
      File is mode 0o644 — anyone on this machine can read it. Run: chmod 600 .env
  [HIGH] history — .zsh_history
      openai key (…29289fad0238) was typed into shell history. Rotate the key, then clear that history entry.
  [MEDIUM] sprawl — .env, .zsh_history
      Same openai key (…29289fad0238) lives in 2 files. Keep one canonical home for it and delete the copies.
  [MEDIUM] sprawl — .codex/config.toml, .config/app.json
      Same anthropic key (…776a5e869d89) lives in 2 files. Keep one canonical home for it and delete the copies.

Rotation checklist (revoke at the provider, then replace):
  - openai: https://platform.openai.com/api-keys
  - github: https://github.com/settings/tokens
  - anthropic: https://console.anthropic.com/settings/keys

After rotating: delete the old value from every file above, clear it from shell history, and re-run keymap to confirm.
```

## Install

No dependencies — Python 3.10+ standard library only.

```bash
git clone https://github.com/techdevfun/keymap
cd keymap
python -m keymap
```

Or install the `keymap` command:

```bash
pip install .
keymap --help
```

## Usage

```bash
python -m keymap                  # scan your home directory
python -m keymap --root ~/work   # scan a different root
python -m keymap .env .codex/config.toml   # scan specific files
python -m keymap --json           # machine-readable output for CI/scripts
```

Exit codes: `0` = no keys found, `1` = keys/findings found,
`2` = usage or I/O error.

## What it checks

| Check | Severity | Meaning |
|---|---|---|
| `world-readable` | high | File holding a key is readable by anyone on the machine (`chmod 600` it) |
| `history` | high | Key was typed into shell history — rotate it, then clear the entry |
| `git-tracked` | high | Key is already tracked by git — rotate now, history rewrites don't un-leak it |
| `not-ignored` | medium | Key sits in a git repo and is not gitignored — one `git add .` from a commit |
| `sprawl` | medium | Same key lives in 2+ files — keep one canonical home, delete the copies |

Recognised providers: Anthropic, OpenAI, Google, GitHub (classic,
fine-grained, OAuth, server-to-server), AWS access key IDs, Slack,
Stripe. Anything assigned to a `*_API_KEY` / `*_TOKEN` / `*_SECRET` /
`*_PASSWORD` variable that matches no known pattern is reported as
`unrecognized` instead of ignored. Placeholder values (`your-token-here`,
`${OPENAI_API_KEY}`, `xxx…`) are skipped.

## How it's different

Secret scanners like gitleaks / trufflehog hunt for leaked secrets in
repos. keymap answers a different question: **the keys you own, on your
own machine, right now** — which agent tools hold them, how many copies
exist, and what to rotate first after a vendor breach. It complements a
repo scanner; it doesn't replace one.

## Roadmap

- Scan 1Password / macOS Keychain references (names only, no secrets).
- `--fix` for the safe fixes only (`chmod 600`, never key deletion).
- Detect keys in agent-tool MCP server configs.
- Spend-anomaly hints: link to each provider's usage page in the report.

## License

MIT — see [LICENSE](LICENSE).
