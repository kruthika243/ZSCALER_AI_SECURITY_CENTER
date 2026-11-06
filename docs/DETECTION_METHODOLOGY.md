# Detection Methodology

## 1. Purpose

The application assesses URLs using two separate sources of evidence:

1. Structural URL characteristics evaluated by deterministic application rules.
2. Google Safe Browsing threat-intelligence lookup results.

These sources are complementary; neither guarantees safety.

## 2. URL normalization and parsing

The analyzer in `core/url_analyzer.py`:
- trims surrounding whitespace;
- rejects empty input;
- rejects ASCII control characters;
- adds `https://` when input does not begin with HTTP or HTTPS;
- parses the URL using Python's `urllib.parse`;
- requires a hostname;
- converts internationalized hostnames to ASCII using IDNA;
- identifies whether the hostname is an IP address.

Only HTTP and HTTPS are supported by the analyzer.

## 3. Extracted structural indicators

| Attribute | Meaning |
|---|---|
| `scheme` | Parsed URL scheme |
| `hostname` | Normalized hostname |
| `path` | URL path |
| `query` | Query string |
| `url_length` | Length of normalized URL |
| `is_https` | Whether HTTPS is used |
| `is_ip_address` | Whether hostname parses as an IP address |
| `subdomain_count` | Number of hostname labels before the final two labels, floored at zero |
| `has_at_symbol` | Whether `@` occurs in the URL |
| `has_dash` | Whether hostname contains a hyphen |
| `has_encoded_characters` | Whether percent-encoded octets occur |
| `special_character_count` | Count of non-alphanumeric characters in the URL |

These are indicators, not proof of maliciousness. Legitimate URLs can contain hyphens, query strings, encoded characters, and multiple subdomains.

## 4. Rule-based structural assessment

The risk engine evaluates extracted indicators using application-defined rules and returns a structural score/classification.

The score is deterministic and rule-based. It is not a machine-learning output or a calibrated probability. A low score cannot establish that a URL is safe.

For exact weights and thresholds, consult the current `core/risk_engine.py` implementation; this document does not restate unverified numeric weights.

## 5. Explainability

The application provides explanations and detection evidence so users can understand observed indicators. Recommendations are guidance based on application rules, not forensic conclusions.

## 6. Google Safe Browsing

The application uses the Google Safe Browsing v4 `threatMatches:find` endpoint:

`https://safebrowsing.googleapis.com/v4/threatMatches:find`

The integration submits a URL lookup using the configured API key and threat/platform/entry-type parameters implemented in `core/google_safe_browsing.py`.

| Status | Interpretation | Does it prove the URL is safe? |
|---|---|---|
| `MATCH` | Google returned a threat match | No; treat as a known threat indicator |
| `NO_MATCH` | No match was returned for this lookup | No |
| `ERROR` | Lookup failed or could not be completed | No; result is inconclusive |

Threat categories depend on the actual API response. A previously tested URL returned `SOCIAL_ENGINEERING`; categories must not be assumed for other URLs.

## 7. Combining assessments

Structural risk and Google status remain separate signals. A confirmed Google Safe Browsing match can elevate the overall verdict to CRITICAL even if the structural score is low.

Previously observed example:

| Signal | Result |
|---|---|
| Structural score | 5/100 |
| Structural classification | LOW |
| Google Safe Browsing | MATCH |
| Threat type | `SOCIAL_ENGINEERING` |
| Overall verdict | CRITICAL |

This is an observed test example, not a universal expected result.

## 8. Limitations

- URL characteristics are heuristics; benign URLs may trigger indicators.
- Malicious URLs can have ordinary-looking structures.
- Newly created threats may not yet appear in threat-intelligence results.
- `NO_MATCH` is not a clean bill of health.
- `ERROR` is not a safe result.
- The application does not fetch page content, inspect redirects, execute scripts, or analyze hosting infrastructure.
- The current implementation does not train or evaluate an ML model.

## 9. Safe testing

Use vendor-provided test URLs for lookup testing and do not open known phishing test URLs. For ordinary behavior tests, use benign example domains and synthetic suspicious-looking strings; do not describe synthetic examples as confirmed malicious.
