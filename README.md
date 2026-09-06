# ECDAT Engine

**Enterprise Cryptographic Discovery & Analysis Tool** — a proof-of-concept
that scans source code for cryptographic usage,scores quantum-migration urgency using Mosca's inequality, and recommends
purpose-aware post-quantum replacements.

This is a small prototype.

## Pipeline

```
sample_repo/*.py
     ↓  
rules/crypto_rules.yaml
     ↓
scan_results.json         
     ↓  (src/ecdat_engine.py)
CryptoFinding → context enrichment → Mosca's inequality →  PQC recommendation
     ↓
ecdat_output.json          
     ↓  (src/generate_dashboard.py)
dashboard.html
```

## How to run

```bash
pip install semgrep --break-system-packages

# scan
semgrep --config rules/crypto_rules.yaml sample_repo/ --json --output output/scan_results.json

cd output
python3 ../src/ecdat_engine.py
python3 ../src/generate_dashboard.py
```

## What this prototype demonstrates

- **Detection**, Semgrep pattern-matches the *shape*
  of code (e.g. a call to `generate_private_key(...)`), not literal text,
  so it generalizes across variable names and import aliases rather than
  only matching the exact code it was written against.
- A canonical `CryptoFinding` internal data model, so the detection source
  (Semgrep today, potentially an imported CBOM or another scanner later)
  is decoupled from the risk/recommendation logic downstream.
- **Mosca's inequality (X + Y vs Z)** applied only to Shor-vulnerable
  public-key primitives (RSA, ECDH) — not blanket-applied to symmetric
  crypto, which faces a different, less urgent threat model.
- **PQC recommendations** — e.g. RSA used for signing routes
  to ML-DSA, not ML-KEM. Purpose, not just algorithm name, determines the
  correct replacement.
- A simple color-coded HTML dashboard.

## Limitations 

- **RSA purpose is currently inferred from key generation, not actual
  usage.** The rule assumes `generate_private_key(...)` implies signing,
  but the same call can precede signing, decryption, or key transport.
  Correctly resolving this needs basic data-flow analysis (tracing the key
  variable to where it's actually used) — not yet implemented.
- **The ECDH rule has the same class of issue.** Detecting
  `ec.generate_private_key(...)` alone can't distinguish an EC key used for
  key exchange from one used for ECDSA signing — only the later call
  (`.exchange()` vs. `.sign()`) reveals that. This was identified during
  development but the fix (matching on the usage call, not the generation
  call) is not yet in this version.
- **Context enrichment (data lifetime, business criticality) is hardcoded
  by filename**, as a deliberate stand-in for real asset metadata — no
  automated tool can infer "this data needs 15 years of protection" from
  code alone; that's a policy input a real system would need supplied.
- **Only 4 detection rules** — narrow by design, covering RSA, ECDH, AES,
  and SHA-1. Real coverage requires many more patterns and languages.
- **Not a real CycloneDX CBOM yet** — `ecdat_output.json` is a
  placeholder (`"bomFormat": "ECDAT-lite"`), not standards-compliant output.
- **No deduplication or confidence scoring** — overlapping findings from
  different rules aren't currently merged, and findings don't carry a
  confidence indicator.

## Future Vision
- Fix the RSA/ECDH purpose-inference issue with basic data-flow tracing
- Real CycloneDX CBOM output via `cyclonedx-python-lib`
- Configurable context input (replacing the filename-based stand-in) via a
  small per-repo config file or CLI prompts
- A working FastAPI backend behind the dashboard
- A second language (Java or JS), extending Semgrep rule coverage
- Dependency-manifest scanning (`requirements.txt`, `package.json`) for
  known-weak crypto libraries, SBOM-style
- A crypto-agility score alongside the risk tier
- CII vs. general-enterprise urgency tagging
- Positioning ECDAT as scanner-agnostic — able to ingest CBOMs from
  existing tools (e.g. IBM's CBOMkit) rather than only its own scanner,
  so the value proposition is the risk/recommendation layer, not
  competing to be a better scanner
