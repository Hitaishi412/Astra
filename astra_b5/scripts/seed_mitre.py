"""
Download and cache MITRE ATT&CK Enterprise data for offline use.

Run with: python scripts/seed_mitre.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import httpx
except ImportError:
    print("httpx not installed. Run: pip install httpx")
    sys.exit(1)

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

OUTPUT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "core", "mitre", "data", "enterprise_attack.json",
)


def download_mitre_data():
    """Download MITRE ATT&CK STIX data and extract technique info."""
    print(f"[MITRE] Downloading from {MITRE_STIX_URL}...")

    response = httpx.get(MITRE_STIX_URL, timeout=60, follow_redirects=True)
    response.raise_for_status()

    stix_data = response.json()
    objects = stix_data.get("objects", [])

    # Extract techniques
    techniques = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        ext_refs = obj.get("external_references", [])
        technique_id = None
        url = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id")
                url = ref.get("url")
                break

        if not technique_id:
            continue

        # Get tactics from kill chain phases
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                tactics.append(phase["phase_name"])

        techniques[technique_id] = {
            "id": technique_id,
            "name": obj.get("name", ""),
            "description": (obj.get("description", ""))[:500],
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "url": url,
        }

    # Save
    output = {
        "version": stix_data.get("spec_version", "unknown"),
        "technique_count": len(techniques),
        "techniques": techniques,
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[MITRE] Saved {len(techniques)} techniques to {OUTPUT_PATH}")


if __name__ == "__main__":
    download_mitre_data()
