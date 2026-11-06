# Testing Documentation

## 1. Purpose

The project uses Pytest to validate core URL parsing, input validation, and structural risk-engine behavior. These are unit-level checks, not a full security audit, penetration test, or end-to-end test of every Streamlit page and external API condition.

## 2. Test organization

```text
tests/
├── test_risk_engine.py
├── test_url_analyzer.py
└── test_validators.py
```

| Module | Scope |
|---|---|
| `test_risk_engine.py` | Structural risk behavior |
| `test_url_analyzer.py` | URL parsing and extracted indicators |
| `test_validators.py` | Input validation and supported URL formats |

## 3. Coverage areas

### Risk engine
- IP-address URL indicator increases risk.
- Clean URL receives a low structural risk score.

### URL analyzer
- HTTPS parsing.
- HTTP handling.
- Default HTTPS when no scheme is supplied.
- IP-address detection.
- Subdomain counting.
- `@` detection.
- Hostname hyphen detection.
- Percent-encoded character detection.
- Empty and whitespace-only input.
- Missing hostname.
- Control-character rejection.

### Validators
- Valid HTTP and HTTPS URLs.
- URL without explicit scheme.
- URL with subdomain and path.
- Empty and whitespace-only input.
- Non-string input.
- Missing hostname.
- Unsupported protocol.
- Out-of-range port.
- Control characters.

## 4. Run tests

Activate the virtual environment and run:

```bash
python -m pytest tests/ -v
```

To inspect discovered tests:

```bash
python -m pytest --collect-only -v
```

To run one module:

```bash
python -m pytest tests/test_url_analyzer.py -v
```

## 5. Reported test result

The project owner reported a successful run with:

| Module | Test count |
|---|---:|
| `test_risk_engine.py` | 2 |
| `test_url_analyzer.py` | 12 |
| `test_validators.py` | 11 |
| **Total** | **25** |

**Reported outcome: 25 passed.** This is based on terminal output shared during development. Re-run the test command on the current checkout before claiming that a later commit passes.

## 6. Manual application verification

The following pages were visually opened during development:
- Dashboard
- URL Scanner
- Threat Intelligence
- Risk Analysis
- Scan History
- Security Reports / PDF preview

A Google Safe Browsing test lookup was observed to return `MATCH` with `SOCIAL_ENGINEERING`; the UI displayed an overall CRITICAL verdict despite a structural score of 5/100.

Visual inspection confirms pages rendered during those sessions. It does not replace automated UI tests or verify every possible data state.

## 7. Known test gaps

The current suite does not by itself verify:
- all Google Safe Browsing response and network-error cases;
- database migration behavior across every historical schema;
- scan-history persistence/retrieval end to end;
- PDF contents through automated assertions;
- Streamlit browser interactions;
- concurrency, performance, or production-load security.

These are candidates for future integration tests.

## 8. Environment warning

During development, the test environment emitted an `urllib3` warning about LibreSSL compatibility on the installed Python runtime. The reported tests still passed. This warning is an environment compatibility notice, not proof that every Google API network scenario works.
