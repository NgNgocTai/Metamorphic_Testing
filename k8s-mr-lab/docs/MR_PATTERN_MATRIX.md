| MR | KP | P-STRUCT | P-REF | P-CLOSED | P-VERDICT | G-REWRITE | G-ADD | G-MODIFY | G-REMOVE | S-TARGET | S-ALL | O-EQUAL | O-PASS-TO-FAIL | O-FAIL-TO-PASS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| MR-01 | KP1 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 |
| MR-02 | KP2 | 0 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 1 | 0 | 0 |
| MR-03 | KP1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 0 |
| MR-04 | KP3 | 1 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 1 | 0 |
| MR-05 | KP3 | 1 | 0 | 1 | 1 | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 1 |
| MR-06 | KP3 | 1 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 1 | 0 |
| MR-07 | KP1 | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 1 | 0 | 1 | 0 | 0 |

Element-level patterns (MRs with an identical combination):
  EP1: MR-04, MR-06   declared: KP3
  EP2: MR-01   declared: KP1
  EP3: MR-02   declared: KP2
  EP4: MR-03   declared: KP1
  EP5: MR-05   declared: KP3
  EP6: MR-07   declared: KP1

Declared families vs element-level patterns:
  KP1 = MR-01, MR-03, MR-07: spans EP2, EP4, EP6 -> coarser than the element level; differs in P-REF, P-STRUCT, S-ALL, S-TARGET
  KP2 = MR-02: spans EP3 -> identical
  KP3 = MR-04, MR-05, MR-06: spans EP1, EP5 -> coarser than the element level; differs in O-FAIL-TO-PASS, O-PASS-TO-FAIL, P-CLOSED
