| MR | Status | Pattern | Property | OWASP K8s 2025 | CWE (control's weakness class) | Spec refs verified | Trivy controls | Kubescape controls |
|---|---|---|---|---|---|---|---|---|
| MR-01 | mvp | KP1 | SP-SYN-MAPPING-ORDER | - | - | 1/1 | KSV-0017, KSV-0048, KSV-0049, KSV-0050, KSV-0112, KSV-0113 | C-0007, C-0015, C-0035, C-0053, C-0057, C-0267, C-0272 |
| MR-02 | mvp | KP2 | SP-RBAC-NS-ROLE-RESOLUTION | K02 | CWE-269 | 1/1 | KSV-0048, KSV-0049, KSV-0050, KSV-0112, KSV-0113 | C-0007, C-0015, C-0035, C-0053, C-0057, C-0267, C-0272 |
| MR-03 | mvp | KP1 | SP-RBAC-ADDITIVE-RULES | K02 | CWE-269 | 1/1 | KSV-0048, KSV-0049, KSV-0050, KSV-0112, KSV-0113 | C-0007, C-0015, C-0035, C-0267, C-0272 |
| MR-04 | mvp_conditional | KP3 | SP-POD-PRIVILEGED | K01 | CWE-250 | 1/1 | KSV-0017 | C-0057 |
| MR-05 | mvp_conditional | KP3 | SP-RBAC-SECRETS-API-GROUP | K02 | CWE-269 | 1/1 | KSV-0113 | C-0015, C-0267 |
| MR-06 | candidate | KP3 | SP-POD-HOST-NAMESPACES | K01 | - | 1/1 | KSV-0009 | C-0041 |
