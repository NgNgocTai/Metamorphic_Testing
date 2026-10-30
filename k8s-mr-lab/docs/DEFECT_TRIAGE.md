# Defect triage protocol

A `VIOLATION` is an *alert*: the MR relation did not hold. It is not a false positive/negative until adjudicated.

| Step | Automated by `triage` | Needs a human |
|---|---|---|
| Re-run the same pair on the same pins, fresh scans, no cache | yes → `CANDIDATE_REPRODUCED` / `NOT_REPRODUCED` | |
| Group into a provisional family (scanner + MR + verdict transition) | yes | split/merge by real root cause |
| Static rule-source evidence (does the rule text even mention the property?) | yes, `triage.json` → `rule_evidence` | interpret it |
| Look up a public upstream issue | by `docs/known_issues.yaml` | check the issue really is the same root cause |
| Reduce the case (object level only) | `--minimize`, "smaller case found, not proven minimal" | |
| Reproducer package | yes, `runs/<run>/reproducers/*` with `reproduce.sh` | run it independently |
| Decide CONFIRMED defect / invalid MR instance / policy scope mismatch | **never** | yes |

Checklist before writing `CONFIRMED` (see doc section 17): diff changes nothing the target control claims to evaluate ·
control really covers the property in this version/mode · normalizer kept resource identity (read raw JSON) ·
versions/policies equal for both scans · reproduced · deduplicated by root cause · upstream searched · labelled
guided/regression vs held-out.

Classes to assign: `NORMALIZATION_ARTIFACT`, `INVALID_MR_INSTANCE`, `NOT_EVALUATED/INCONCLUSIVE`, `ENVIRONMENT_MISMATCH`,
`CONTROL_SCOPE_MISMATCH`, `CROSS_SCANNER_OBSERVATION`, `CONFIRMED_SCANNER_DEFECT`.
