# Contributing to Babel

Thanks for your interest in improving Babel! This guide covers how to set up a dev
environment, run the checks, and submit changes.

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the same license as the project.

## Reporting issues

- **Bugs / features:** open a GitHub issue with clear reproduction steps, your Kibana/
  Elasticsearch version, and relevant logs.
- **Security vulnerabilities:** **do not** open a public issue — follow the process in
  [SECURITY.md](SECURITY.md).

## Project layout

Babel is a Kibana plugin (TypeScript/React) backed by an out-of-process Python **Sigma API**.
See the **Architecture** and **Project structure** sections of the [README](README.md) for the
full map. The pieces you'll most likely touch:

- `public/` — React UI (Elastic UI / EUI)
- `server/` — Kibana server plugin (`routes/`), the FastAPI Sigma API (`server/api/`), and the
  optional Claude MCP server (`server/mcp/`)
- `scripts/build.js` — build orchestrator

## Dev setup

**Prerequisites:** Node.js 20+, Docker + Docker Compose, and (for the Sigma API) Python 3.12.

```bash
git clone <your-fork-url>
cd babel_elastic_ai
npm install
cp .env.example .env            # set ELASTIC_PASSWORD, KIBANA_SYSTEM_PASSWORD, KIBANA_ENCRYPTION_KEY
KIBANA_VERSION=9.3.4 npm run build   # one-time plugin build (required before first compose up)
docker compose up --build -d    # Elasticsearch + Kibana (with Babel) + Sigma API
```

Kibana comes up at http://localhost:5601. See the README's **Quick start** for the full walkthrough.

> The plugin's `kibanaVersion` is pinned in `kibana.json`. If you target a different Kibana,
> rebuild with `KIBANA_VERSION=<your-version> npm run build`.

## Running the checks (match CI before opening a PR)

```bash
# Frontend / plugin
npx tsc --noEmit                # type-check (must pass)
npm test                        # Jest unit tests

# Sigma API (Python)
pip install -r server/api/requirements.txt
cd server/api && REQUIRE_AUTH=true PLUGIN_ROOT="$(git rev-parse --show-toplevel)" \
  python -m pytest tests/ -q
```

CI (`.github/workflows/ci.yml`) runs the same: typecheck + Jest + plugin build for the UI, and
pytest for the Sigma API. **All checks must be green** for a PR to merge.

## Coding guidelines

- **Match the surrounding code** — naming, structure, comment density, and EUI usage. Look at a
  nearby file before introducing a new pattern.
- **TypeScript:** `tsc --noEmit` must pass with no new errors. Prefer reusing existing
  components/services (e.g. `AiProviderSettings.tsx`, `services/api.ts`) over new ones.
- **Python:** keep the Sigma API typed and tested; add/extend tests under `server/api/tests/`.
- **No secrets in the repo.** `.env` and `.mcp.json` are git-ignored — never commit credentials,
  API keys, or tokens. Use `.env.example` for new config keys.
- **Third-party code:** if you add a dependency that ships in the distribution, add an entry to
  [NOTICE](NOTICE).

## Submitting a pull request

1. Branch from the default branch and keep PRs focused.
2. Write clear commit messages (imperative mood; explain the *why*).
3. Add or update tests for behavior changes.
4. Make sure `tsc`, Jest, and the API tests pass locally.
5. Open the PR describing the change and linking any related issue. Be ready to iterate on review.

Thanks for contributing! 🛡️
