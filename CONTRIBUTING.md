# Contributing

Thanks for taking the time to improve AI-Native Security. This project is a
self-hosted security tool, so changes are reviewed with the same care you would
expect from a security product: tests, migrations and documentation travel with the
code.

## Ways to contribute

- **Bugs** — open an issue with the version, the exact command, and the relevant
  log line. Redact tokens before pasting.
- **Scanner coverage** — new adapters, better parsers, or fixtures captured from a
  real scanner run.
- **AI prompts and agents** — better evidence selection, clearer schemas, new
  guardrail tests.
- **Frontend** — the dashboard is plain React + Tailwind; small, focused PRs are
  welcome.
- **Documentation** — corrections are as valuable as features, especially where a
  doc claims something the code does not do.

## Development setup

```bash
git clone https://github.com/hungpt99-dev/ai-native-security.git
cd ai-native-security
cp .env.example .env
```

Backend (Python 3.12):

```bash
cd backend
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
export ANS_DATABASE_URL=postgresql+psycopg://security:security@localhost:5432/security
export ANS_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

Worker and scheduler run as separate processes (`python -m app.workers.worker`,
`python -m app.scheduler.scheduler`). PostgreSQL is easiest to run with:

```bash
docker run -d --name ans-postgres -p 5432:5432 \
  -e POSTGRES_USER=security -e POSTGRES_PASSWORD=security -e POSTGRES_DB=security \
  postgres:16-alpine
```

Frontend (Node 20+):

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173, proxies /api to :8000
```

## Quality gates

Run these before opening a pull request; CI runs the same commands.

```bash
cd backend
pytest -q          # integration tests create a real security_test database
ruff check app tests
mypy app

cd ../frontend
npm run build      # tsc -b && vite build
```

The test suite must stay offline: AI tests use `FakeProvider`, and vulnerability
feeds are mocked. If a change needs network access to be tested, it is probably
not shaped correctly yet.

## Database changes

```bash
cd backend
alembic revision --autogenerate -m "short description"
alembic upgrade head
alembic downgrade -1   # verify the rollback works before pushing
alembic upgrade head
```

Additive migrations only. A migration that drops a column or constraint must
explain why in the PR description and in the migration docstring.

## Adding an AI capability

1. Define the output as a Pydantic model in `app/modules/ai/schemas/outputs.py`.
2. Add a prompt in `app/modules/ai/prompts/` and register it. A prompt change
   **requires a version bump** — the version is recorded on every execution.
3. Keep the provider call in an agent (`app/modules/ai/agents/`), persistence in a
   service (`app/modules/ai/services/` or the owning module).
4. Post-process the model output: drop evidence keys that were not supplied, force
   `requires_human_review` when information is missing, and never let AI write
   deterministic state (finding status, verification status, CVSS).
5. Test it with `FakeProvider` — both the happy path and a malformed answer.

Boundary rule: no module outside `app/modules/ai/` may import
`app.modules.ai.providers`. Deterministic modules must stay runnable with AI
disabled, and `tests/integration/test_ai_workflow.py` plus
`tests/unit/test_ai_provider.py` enforce the important ones.

## Pull requests

- One concern per PR; a formatting pass in an unrelated file makes review harder.
- Describe the behaviour change, the test that proves it, and any migration risk.
- Update the docs that describe the thing you changed (`docs/`, `README.md`).
- Do not include real credentials, repository tokens, or customer data in fixtures.
- Screenshots are welcome for UI changes; put them in `docs/screenshots/`.

## Reporting a security issue

Please do **not** open a public issue for a vulnerability in this platform. Use
GitHub's private vulnerability reporting on the repository, or contact the
maintainer directly. The threat model and the controls already in place are
documented in [`docs/SECURITY.md`](docs/SECURITY.md); a report is most useful when
it names the control that failed.

## Code style

- Python 3.12, full type hints, `ruff` line length 110, `mypy` clean.
- Services own transactions; repositories own queries; routers only validate and
  serialise.
- Enum values are stored as strings with `CHECK` constraints, not PostgreSQL enums.
- Every finding-affecting decision must be explainable from stored rows.

## License

No open-source license is granted. Contributions are accepted on the understanding
that the maintainer may use them in this project under the terms in
[`README.md`](README.md#license).
