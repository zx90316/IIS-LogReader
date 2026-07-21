# Contributing

Thanks for your interest in improving IIS Log Reader.

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
pytest -q
```

## Guidelines

1. Keep changes focused; match existing code style.
2. Do not commit local `app.config`, `cache/`, virtualenvs, or real production logs.
3. Add or update tests when you change parser, filter, or stats logic.
4. UI strings in the app are Traditional Chinese; README / docs may stay in English.

## Pull requests

- Describe **why** the change is needed.
- Note any user-visible behavior changes.
- Ensure CI / `pytest` passes.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
