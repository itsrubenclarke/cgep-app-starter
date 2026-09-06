# OSCAL artifacts

Machine-readable statements of what this system implements, in OSCAL 1.2.1.

| File | What it is |
|---|---|
| `catalogs/cmmc-l2-subset-catalog.json` | The 7 CMMC Level 2 controls this component implements. Authored here, see below. |
| `profiles/cge-p-minimum.json` | Selects those 7 controls out of the catalog. |
| `components/acme-health-intake-component.json` | The Patient Intake API: 8 implemented requirements, one per gap in `GAPS.md`, each naming the real Terraform resource that satisfies it and linking to a signed evidence bundle in the vault. |
| `trestle-validate.txt` | Captured validation output. Regenerate with the commands below. |

## Why the catalog is authored here

No official OSCAL catalog exists for the framework this project declares. NIST's
`oscal-content` repository publishes SP 800-171 only for Rev 3, using renumbered
`SP_800_171_03.xx.xx` identifiers. CMMC 2.0 Level 2 is defined against Rev 2,
whose identifiers (`AC.L2-3.1.5` and so on) are what every control citation in
this repo uses. Every published tag back to `v1.0.0` was checked; none carry a
Rev 2 catalog.

Rather than renumber the whole project to Rev 3 (which would misalign the OSCAL
from the framework actually being certified against) or cite a `source` URL whose
identifiers don't match ours, this catalog holds just the 7 controls the component
actually implements, with prose drawn from CMMC's public practice descriptions.
`WRITEUP.md` covers the trade-off in full.

## Validating

The files here use plain relative paths so they resolve on their own. To
re-validate them in a fresh trestle workspace:

```bash
pip install compliance-trestle
mkdir trestle-check && cd trestle-check && trestle init

mkdir -p catalogs/cmmc-l2-subset component-definitions/acme-health-intake profiles/cge-p-minimum
cp ../oscal/catalogs/cmmc-l2-subset-catalog.json      catalogs/cmmc-l2-subset/catalog.json
cp ../oscal/components/acme-health-intake-component.json component-definitions/acme-health-intake/component-definition.json
cp ../oscal/profiles/cge-p-minimum.json               profiles/cge-p-minimum/profile.json

trestle validate -a
# → VALID for all three models

trestle author profile-resolve -n cge-p-minimum -o cge-p-minimum-resolved
# → resolves to exactly the 7 controls listed in trestle-validate.txt
```

Schema validity alone doesn't prove the profile actually points at a real catalog,
which is why `profile-resolve` is run too: it fails if the reference is broken, and
succeeds only by pulling the 7 controls through.
