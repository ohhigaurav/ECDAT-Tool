import json
from dataclasses import dataclass, asdict, field

@dataclass
class CryptoFinding:
    algorithm: str
    purpose: str         
    source: str
    line: int
    confidence: str = "high"          
    data_lifetime_years: int = 0   
    business_criticality: str = "unknown"
    migration_effort_years: int = 0   
    crqc_horizon_years: int = 10 
    risk_tier: str = ""
    recommendation: str = ""
    rationale: str = ""

CONTEXT_PROFILES = {
    "auth.py":          {"data_lifetime_years": 15, "business_criticality": "critical",  "migration_effort_years": 4},
    "payments.py":       {"data_lifetime_years": 15, "business_criticality": "critical",  "migration_effort_years": 4},
    "internal_tool.py":  {"data_lifetime_years": 1,  "business_criticality": "low",       "migration_effort_years": 1},
}

RECOMMENDATIONS = {
    ("RSA", "signature"):        ("ML-DSA / SLH-DSA", "Signature-purpose RSA maps to a PQC signature scheme, not a KEM."),
    ("ECDH", "key_establishment"): ("ML-KEM / hybrid KEM", "Key-establishment use maps to a PQC key-encapsulation mechanism."),
    ("AES", "encryption"):        ("AES-256 (if not already)", "Grover's algorithm only halves effective symmetric strength — raise key size, not urgent like public-key crypto."),
    ("SHA-1", "hashing"):         ("SHA-256 or SHA-3", "SHA-1 is classically broken already — a hygiene issue, not primarily a quantum one."),
}
def mosca_risk_tier(x_lifetime: int, y_migration: int, z_horizon: int) -> str:
    total = x_lifetime + y_migration
    if total > z_horizon:
        return "CRITICAL"
    elif total > z_horizon - 3:
        return "HIGH"
    elif total > 0:
        return "MEDIUM"
    return "LOW"


def load_semgrep_findings(path: str) -> list[CryptoFinding]:
    with open(path) as f:
        data = json.load(f)
    findings = []
    for r in data["results"]:
        meta = r["extra"]["metadata"]
        fname = r["path"].split("/")[-1]
        ctx = CONTEXT_PROFILES.get(fname, {"data_lifetime_years": 5, "business_criticality": "medium", "migration_effort_years": 2})

        f_obj = CryptoFinding(
            algorithm=meta["algorithm"],
            purpose=meta["purpose"],
            source=r["path"],
            line=r["start"]["line"],
            data_lifetime_years=ctx["data_lifetime_years"],
            business_criticality=ctx["business_criticality"],
            migration_effort_years=ctx["migration_effort_years"],
        )
        findings.append(f_obj)
    return findings


QUANTUM_VULNERABLE_PURPOSES = {"signature", "key_establishment"}

def analyze(findings: list[CryptoFinding]) -> list[CryptoFinding]:
    for f in findings:
        if f.purpose in QUANTUM_VULNERABLE_PURPOSES:
            f.risk_tier = mosca_risk_tier(f.data_lifetime_years, f.migration_effort_years, f.crqc_horizon_years)
        else:
            f.risk_tier = "LOW" if f.algorithm != "SHA-1" else "MEDIUM"
        rec = RECOMMENDATIONS.get((f.algorithm, f.purpose))
        if rec:
            f.recommendation, f.rationale = rec
        else:
            f.recommendation, f.rationale = ("No PQC migration needed", "Not a quantum-vulnerable primitive at this key size.")
    return findings


def print_report(findings: list[CryptoFinding]):
    tier_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings_sorted = sorted(findings, key=lambda f: tier_order.get(f.risk_tier, 4))

    counts = {}
    for f in findings:
        counts[f.risk_tier] = counts.get(f.risk_tier, 0) + 1

    print("=" * 78)
    print("ECDAT — Migration Command Center (demo)")
    print("=" * 78)
    print(f"{len(findings)} cryptographic assets discovered\n")
    for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if tier in counts:
            print(f"   {tier:<10} {counts[tier]}")
    print()
    print("-" * 78)

    for f in findings_sorted:
        print(f"\n[{f.risk_tier}] {f.algorithm} ({f.purpose}) — {f.source}:{f.line}")
        print(f"   Data lifetime (X):      {f.data_lifetime_years} years")
        print(f"   Migration effort (Y):   {f.migration_effort_years} years")
        print(f"   CRQC horizon (Z):       {f.crqc_horizon_years} years")
        print(f"   Mosca: {f.data_lifetime_years} + {f.migration_effort_years} "
              f"{'>' if f.data_lifetime_years + f.migration_effort_years > f.crqc_horizon_years else '<='} {f.crqc_horizon_years}")
        print(f"   Business criticality:   {f.business_criticality}")
        print(f"   Recommendation:         {f.recommendation}")
        print(f"   Why:                    {f.rationale}")

    print("\n" + "=" * 78)


def export_cbom_lite(findings: list[CryptoFinding], path: str):
    #simplified stand-in for CycloneDX CBOM output.
    out = {"bomFormat": "ECDAT-lite", "components": [asdict(f) for f in findings]}
    with open(path, "w") as f:
        json.dump(out, f, indent=2)


if __name__ == "__main__":
    findings = load_semgrep_findings("output/scan_results.json")
    findings = analyze(findings)
    print_report(findings)
    export_cbom_lite(findings, "output/ecdat_output.json")
    print(f"\nStructured output written to output/ecdat_output.json")
