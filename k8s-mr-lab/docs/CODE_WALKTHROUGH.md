# Code walkthrough: từ một seed YAML tới một assessment

Tài liệu cho người muốn hiểu framework mà không đọc hết mã. Mọi tên hàm/lớp dưới đây đã được đối chiếu với mã nguồn
trên nhánh `research/mr-patterns`. Thuật ngữ: **SUT** là scanner (Trivy, Kubescape), không phải Kubernetes.

## 1. Các khái niệm dữ liệu

| Khái niệm | Ở đâu | Là gì |
|---|---|---|
| `ResKey` | `model.py` | `(apiGroup, kind, namespace, name)`: danh tính một object; cluster-scoped có namespace `""` |
| `ConfigBundle` | `bundles.py` | danh sách object đã parse (strict: cấm khóa trùng) + `index()`, `find()`, `of_kind()`, `clone()`, `dump()`, `semantic_digest()`, `text_digest()`, `write()` (ghi và trả `Span` = dòng của từng object) |
| `MetamorphicRelation` | `transforms/base.py` | một MR thực thi: `applicable`, `generate_parameters`, `transform`, `validate_pair`, `targets`; metadata gắn từ catalog bằng `bind(spec)` |
| `PerCandidateMR`, `ControlledChange` | `transforms/patterns.py` | khuôn dùng chung cho MR "một case mỗi candidate" và MR "đổi đúng một trường" |
| `PolicyMapping` | `registry.py` | đọc `config/policy-mapping.yaml`: control nào được so cho MR nào, trên target nào, áp dụng cho kind nào |
| `ScannerInvocation` | `model.py` | lệnh, exit code, version, mode, policy digest, đường dẫn raw JSON, `error` (có `error` thì là SCAN_ERROR) |
| `CanonicalVerdict` / `NormalizedReport` | `model.py` | verdict của *một* control trên *một* resource: `PASS / FAIL / NOT_EVALUATED / UNKNOWN / EXCLUDED`, kèm `evidence` |
| `KeyResult` / `Assessment` | `model.py` | kết quả so sánh từng `(control, resource)` và kết luận của MR cho một cặp |
| `CaseResult` | `runner.py` | một dòng kết quả: MR, seed, params, trạng thái, invocation, thời gian, sha256 |

**Hai tầng trạng thái, không được lẫn:** verdict của scanner (`PASS/FAIL/NOT_EVALUATED` trên một control×resource) và
kết quả của MR (`PASS/PARTIAL/VIOLATION/SKIP/INVALID_SOURCE/INVALID_PAIR/INCONCLUSIVE/SCAN_ERROR/ENVIRONMENT_MISMATCH`).
"MR PASS" nghĩa là quan hệ được thỏa, không có nghĩa scanner cho PASS.

## 2. Nạp MR

```
mrs/catalog.yaml ──read_specs()──▶ kiểm schema (trường, kiểu, id, relation, status, template)
                                     │
transforms/__init__.py  import mọi module ─▶ @implements("MR-xx") ghi class vào IMPLEMENTATIONS
                                     │
registry.load_catalog() ──▶ {id: instance}; mỗi instance.bind(spec) nhận name/category/pattern/relation/...
registry.active_mrs(catalog, ids) ──▶ mặc định bỏ status=candidate; id lạ ném UnknownMRError (CLI thoát mã 2)
```

## 3. Luồng một lần chạy (`k8s-mr-lab run`)

`cli.cmd_run` tạo `Runner(scanner, mapping, catalog, out_dir)` rồi gọi `Runner.run_seed(seed_dir, mr_ids, max_cases)`
cho từng seed, sau đó `report.write_run(...)` ghi `results.json`, `results.csv`, `comparisons.csv`, `environment.lock.json`.

```mermaid
sequenceDiagram
    participant RS as Runner.run_seed
    participant MR as MetamorphicRelation
    participant RP as Runner.run_pair
    participant SC as Scanner.execute
    participant NO as normalize()
    participant CK as checker.check
    RS->>RS: load_bundle(seed); validate_source() (lỗi → INVALID_SOURCE, không scan)
    loop mỗi MR trong active_mrs()
        RS->>RS: mapping.supports(mr, scanner)? (không → SKIP mr_not_mapped_for_scanner)
        RS->>MR: applicable(source) (không → SKIP <lý do>)
        RS->>MR: generate_parameters(source, max_cases)
        loop mỗi params
            RS->>RP: run_pair(seed_id, source, mr, params)
            RP->>MR: transform(source, params) → (follow-up, trace)
            RP->>MR: validate_pair(source, follow-up, params)
            Note over RP: ghi source/, followup/, diff.patch, diff.json, trace.json
            RP->>RP: ≠ VALID_PAIR → INVALID_PAIR / INCONCLUSIVE (không scan)
            RP->>RP: static_keys(mr, entries, kinds, source, params) (rỗng và không all_failures → SKIP)
            RP->>SC: _scan(source) ; _scan(follow-up)   (cache theo text_digest)
            SC-->>RP: ScannerInvocation + raw JSON
            RP->>NO: normalize(scanner, raw, bundle, spans, kinds)
            RP->>RP: lỗi invocation → SCAN_ERROR; (version, mode, policy) khác → ENVIRONMENT_MISMATCH
            RP->>CK: check(mr, full_keys(...), r_source, r_followup)
            CK-->>RP: Assessment (PASS / PARTIAL / VIOLATION / INCONCLUSIVE / SKIP)
            Note over RP: _finish(): assessment.json, provenance.json
        end
    end
```

Thứ tự trong `run_pair` là có chủ đích: **cặp không hợp lệ không bao giờ được quét** (không tốn invocation, không tạo
cảnh báo giả), và **hai lần quét khác môi trường không bao giờ được so**.

## 4. Từng bước, chuyện gì có thể sai

| Bước | Hàm | Input → Output | Vì sao cần | Lỗi có thể gặp |
|---|---|---|---|---|
| Nạp seed | `bundles.load_bundle` | thư mục/tệp YAML → `ConfigBundle` | parse strict (khóa trùng là lỗi) | YAML sai; khóa trùng |
| Kiểm nguồn | `validation.validate_source` → `ConfigBundle.problems()` | bundle → danh sách lỗi | seed thiếu phụ thuộc làm MR vô nghĩa | binding trỏ Role không có (seed `invalid-missing-role`) |
| Precondition | `mr.applicable` | bundle → `(ok, lý do)` | chỉ áp MR nơi nó có nghĩa | precondition quá rộng → cặp hợp lệ về cấu trúc nhưng sai ngữ nghĩa |
| Sinh tham số | `mr.generate_parameters` | bundle → list params | mỗi candidate là một case | trùng case giữa seed giống nhau (xử lý ở khử trùng báo cáo) |
| Biến đổi | `mr.transform` | (bundle, params) → (follow-up, trace) | không bao giờ sửa source (`clone()`) | sửa nhầm source (gate `mr validate` bắt) |
| Kiểm cặp | `mr.validate_pair` (KP3: `ControlledChange` + `validation.expect_single_change`) | → `VALID_PAIR / INVALID_PAIR` | chứng minh follow-up khác đúng như MR nói | **chỉ là cấu trúc**, không chứng minh ngữ nghĩa |
| Scope | `checker.static_keys` (+ `mr.targets`, mapping) | → list `(control, ResKey)` | chỉ so những gì MR cho phép | scope rộng → so cả finding hợp lệ trên object mới (ví dụ Role decoy) |
| Quét | `Scanner.execute` (`scanners/base.py`) | thư mục → `ScannerInvocation` + JSON | cùng binary, cùng policy cho cả hai phía | thiếu binary, timeout, JSON hỏng, sai pin → SCAN_ERROR |
| Chuẩn hóa | `normalize/trivy.py`, `normalize/kubescape.py` | raw JSON → `NormalizedReport` | đưa verdict về `(control, resource)` | Trivy: PASS chỉ là **suy luận** (không có FAIL gắn vào resource); Kubescape: verdict RBAC gộp theo bộ (SA, Role, RoleBinding) |
| So sánh | `checker._compare` qua `checker.RELATIONS` | hai verdict → ok / violation / inconclusive | quan hệ MR là oracle | verdict thiếu → inconclusive, **không bao giờ** suy thành PASS |
| Kết luận | `checker.check` | → `Assessment` | có violation → VIOLATION; một phần không có verdict → PARTIAL | failure không gắn được resource → INCONCLUSIVE toàn cặp |
| Báo cáo | `report.write_run`, `report.case_row` | → CSV/JSON | `results.csv` chỉ điền verdict ở dòng VIOLATION; verdict từng key nằm ở `comparisons.csv` | đọc nhầm `results.csv` như bằng chứng PASS→FAIL |
| Triage | `triage.triage_run` (+ `minimize_case`, `write_reproducers`) | run dir → `triage.json`, reproducers | chạy lại, gom họ (`family_signature`), đối chiếu `docs/known_issues.yaml` | **không bao giờ** gắn CONFIRMED |

## 5. Hai loại kiểm tra, khác nhau về bản chất

* **Kiểm tra cấu trúc (máy làm):** `read_specs` (schema), `mr_tools.check_traceability` + `check_template` (truy vết),
  `mr_tools.exercise` (MR sinh cặp hợp lệ, xác định, không sửa source), `validate_pair` từng cặp.
* **Lập luận ngữ nghĩa (người làm):** vì sao phép biến đổi giữ nguyên hoặc đổi đúng một thuộc tính Kubernetes, và vì sao
  control được so thật sự cam kết thuộc tính đó. Ghi trong `security_properties.yaml` (trích dẫn có `verified`),
  `docs/MR_SEMANTIC_REVIEW_CHECKLIST.md` và case study như `docs/case_studies/MR02_SEMANTIC_CASE_STUDY.md`.

## 6. Công cụ để đọc một kết quả

```bash
k8s-mr-lab mr list                       # catalog
k8s-mr-lab mr explain MR-02              # property, pattern, template, mapping, precondition, giới hạn, vị trí code, test
k8s-mr-lab mr explain MR-02 --case docs/evidence/p0_reverification_2026-11-01/kubescape/cases/MR-02__rbac-workload__66de14dad8
k8s-mr-lab mr patterns                   # ma trận MR × phần tử template (phương pháp Bảng 4 của MST-wi)
k8s-mr-lab mr trace                      # ma trận truy vết property → MR → control
k8s-mr-lab mr validate                   # cổng cấu trúc (không cần scanner)
```

`mr explain --case` chỉ **đọc** evidence đã lưu (trace, diff, assessment, provenance, triage); nó không tính verdict.
File nào thiếu thì in `NOT_AVAILABLE`.
