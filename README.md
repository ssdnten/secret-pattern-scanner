# Secret Pattern Scanner

Scan a local directory for private key markers and suspicious credential assignments, with redacted findings.

Educational cybersecurity portfolio project. Built with AI assistance and supplied with synthetic fixtures and automated tests. It is a learning implementation, not a production security product.

## Quick start

Requires Python 3.11 or newer. Uses only the Python standard library; no pip installation or network access is needed.

From this repository's directory:

```console
python main.py samples
```

On Windows, use `py` in place of `python` if that is your installed launcher. Output is JSON on stdout. To save it, append `> report.json` in your terminal. Paths are relative to your current working directory.

## How it works

Use bounded text-file scanning and regular expressions; emit path, line, rule and a fixed redaction string. Findings exit 1; operational errors exit 2. No original secret value or source line is printed.

## Input and example

The `samples/` directory contains the complete minimal input schema and fictional data. The checked `samples/expected-output.json` records the output of the quick-start command (for the integrity monitor, the final check command).

## Tests

```console
python -m unittest discover -s tests -v
```

Tests cover core behavior, boundary cases and invalid input. GitHub Actions is configured to run them on Windows and Ubuntu with Python 3.11–3.13; see the Actions tab for actual remote results.

## Limitations

Heuristic assignment names only; does not inspect Git history, archives, multiline values or every token format. Skipped files are reported. A clean report does not prove absence of secrets.

Successful analysis exits 0 unless stated otherwise above; command/input errors exit 2. Findings are not automatically remediated. Only use data you are authorized to analyze. Do not commit real credentials, customer logs or personal data.

## Learning notes

See [LEARNING_RU.md](LEARNING_RU.md) for an exercise and interview questions. Explain the algorithm, run the demo and implement an extension before presenting this as a skill you can use independently.
