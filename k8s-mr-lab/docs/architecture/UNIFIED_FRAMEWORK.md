# Framework thống nhất: một đặc tả MR, một cơ chế mapping/scope, một pipeline

Tài liệu này mô tả kiến trúc **duy nhất** đang chạy. Không có phiên bản song song, không có đường tương thích ngược, không có chế độ chạy kép. Kiến trúc cũ chỉ còn trong lịch sử git và evidence thô (xem `LEGACY_TO_UNIFIED_AUDIT.md`).

## 1. Bốn nguồn sự thật, mỗi thuộc tính đúng một nơi

| Câu hỏi | Nguồn duy nhất | Do ai viết |
|---|---|---|
| MR là gì, nhắm yêu cầu nào, đụng object nào, khai báo target nào | `mrs/catalog.yaml` | người (kèm lý do) |
| Control của scanner **đọc** và **báo cáo trên** kind nào | `config/control-registry.yaml` | **sinh tự động** từ policy đã pin (`scripts/derive_control_registry.py`), không sửa tay |
| MR nào so control nào, trên target nào, vai trò gì, vì sao | `config/policy-mapping.yaml` | người (kèm lý do) |
| Yêu cầu bảo mật (OWASP/CWE/K8s docs) | `mrs/requirements.yaml` | người, từ nguồn chính thức |

Quan hệ MR ↔ yêu cầu chỉ nằm ở catalog (`requirements: [{id, coverage}]`, `origin`). `requirements.yaml` chỉ nói `uncovered:` cho yêu cầu chưa có MR; trạng thái COVERED/PARTIAL được **suy ra** bởi `mr requirements`.

`policy-mapping.yaml` và registry **không gộp** vì trách nhiệm khác nhau: một bên là sự kiện về scanner (sinh ra, kiểm chứng bằng sha256 của rego/JSON nguồn), bên kia là quyết định của người nghiên cứu (so cái gì, vì sao). Chúng chỉ trùng nhau ở "control này đọc kind nào", và phần đó chỉ có trong registry.

## 2. Đặc tả MR (catalog) — một schema cho mọi MR

Trường bắt buộc (kiểm bởi `registry.read_specs`): `id, name, category, status, pattern, property_id, property, relation, scope, preconditions, transformation, pair_checks, counterexample, limits, template`, cộng bốn trường của khung thống nhất:

| Trường | Ý nghĩa | Ràng buộc |
|---|---|---|
| `origin` | MR sinh ra thế nào: `prospective` (dẫn xuất từ yêu cầu trước), `retrospective` (viết trước, gắn nhãn yêu cầu sau), `empirical` (từ quan sát scanner), `semantic` (từ ngữ nghĩa K8s), `sanity` (kiểm tra nền) | `prospective`/`retrospective` bắt buộc có ≥ 1 requirement |
| `requirements` | `[{id: R0x, coverage: full\|partial}]` | id phải có trong `requirements.yaml` |
| `touches` | kind mà phép biến đổi thay đổi (`workload` = nhóm kind workload; `["*"]` = viết lại mọi object) | khác rỗng |
| `targets` | các selector mà `targets()` của implementation có thể trả về | thuộc từ vựng của mapping; `["ALL_OF_KIND"]` đi cùng `touches: ["*"]` |

Implementation chỉ gắn bằng `@implements("MR-xx")` trên giao diện chung (`applicable`, `generate_parameters`, `transform`, `validate_pair`, `targets`; tùy chọn `rule_probe`). Logic riêng của MR (cách biến đổi, cách tìm target) nằm **trong class MR**, không nằm trong core.

## 3. Ánh xạ và phân giải scope

`policy-mapping.yaml` (schema `mr-mapping/1`):

* `targets:` từ vựng selector và kind của từng selector (`bound_role`, `role_direct`, `subject_sa`, `rolebinding`, `workload`).
* `mrs.<MR>.<scanner>: [{control, target, reason, role}]`. `role: property` (mặc định) là so sánh phải **quan sát được** thứ MR đổi; `role: control` là đối chứng âm cố ý (không được phản ứng).
* `unsupported.<MR>.<scanner>: <lý do>`: mọi cặp (MR, scanner) không có entry **phải** được giải thích ở đây.

Phân giải lúc chạy (`checker.static_keys`): với mỗi entry, lấy `mr.targets(source, params)[target]` (hoặc mọi object khi `ALL_OF_KIND`), lọc theo kind mà control báo cáo (`registry.reports_on`). Nếu `targets()` trả selector chưa khai báo trong catalog thì ném lỗi.

### Kiểm tĩnh (`mr validate` → `mr_tools.check_mapping`)

Một bộ luật cho mọi MR:

1. **Không mồ côi**: MR trong mapping có trong catalog; control có trong registry; mọi control của registry được dùng; không có khoảng trống im lặng (cặp MR×scanner phải có entry hoặc lý do `unsupported`, không được cả hai).
2. **Chiến lược target**: target thuộc từ vựng **và** được MR khai báo; `ALL_OF_KIND` chỉ cho MR có `touches: ["*"]`; entry không chết (control thật sự báo cáo trên kind của target).
3. **Vai trò**: `property` phải quan sát được thay đổi (Trivy `judged_object`: kind bị đổi ∩ kind của target ∩ `reports_on`; Kubescape `all_matched_kinds`: kind bị đổi ∩ `reads`); `control` phải **không** quan sát được (nếu quan sát được thì đó là so sánh property bị gán nhãn sai).
4. Một control không có hai vai trò khác nhau trong cùng (MR, scanner).

### Phạm vi của control: "không thể đánh giá" khác "không được đánh giá"

Registry mô tả mỗi control bằng `reads` (kind nó nạp vào đầu vào), `reports_on` (kind mà verdict của nó có thể gắn vào) và, với control tổng hợp (aggregator của Kubescape), một `scope_rule` có tên (`rbac_triple_member`): trong các kind được tổng hợp (`ServiceAccount`, `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding`), control chỉ **đánh giá được** những đối tượng nằm trong một chuỗi subject → binding → role của chính bundle. Quy tắc nằm ở `checker.SCOPE_RULES` (dùng chung, không có ngoại lệ theo MR) và được suy ra từ đối tượng nguồn, không từ output của scanner.

| Tình huống | Xử lý |
|---|---|
| Đối tượng ngoài phạm vi của control (ServiceAccount hay Role không được bind) | không so sánh; ghi vào `scope.json` của case (`out_of_control_scope`) |
| Trong phạm vi nhưng scanner không đánh giá ở cả hai phía | giữ nguyên khóa, `INCONCLUSIVE` (không bao giờ PASS) |
| Có verdict ở một phía, thiếu ở phía kia | `INCONCLUSIVE`, hiện rõ |
| Có verdict ở cả hai phía | so quan hệ: thỏa hoặc `VIOLATION` |
| MR có `all_failures` | mọi FAIL ở một trong hai báo cáo vẫn được so, kể cả ngoài phạm vi đã phân giải |

Quy tắc được kiểm trên báo cáo Kubescape thật của Kalm-Benchmark: mọi đối tượng trong phạm vi đều có verdict, không đối tượng ngoài phạm vi nào có verdict (0 ngoại lệ trên 408 cặp đối tượng×control). `mr validate` từ chối `scope_rule` không có trong `SCOPE_RULES` và cảnh báo selector được MR khai báo nhưng không control nào so sánh.

Đây là điều kiện **cần**, không phải đủ, để control phụ thuộc thật vào trường bị đổi (xem `docs/INFORMATIVE_COMPARISON_ANALYSIS.md`).

## 4. Một pipeline thực thi

`Runner.run_pair` là đường duy nhất: transform → `validate_pair` → quét cả hai phía bằng cùng scanner/version/policy → chuẩn hóa → `check` (oracle quan hệ) → `informative.annotate` → `assessment.json`.

`annotate` gắn vào **mỗi so sánh** các cột tách bạch:

| Cột | Trả lời |
|---|---|
| `outcome` | quan hệ MR thỏa hay vi phạm (ok / violation / inconclusive) |
| `role` | so sánh property hay đối chứng âm |
| `tier` | verdict có **quan sát được** thuộc tính không: INFORMATIVE, WEAK (PASS suy luận của Trivy), CONTROL, UNINFORMATIVE (bằng nhau theo cấu trúc), INCONCLUSIVE |
| `basis`, `engaged` | PASS tường minh hay suy luận; có FAIL gắn vào resource ở một phía |

Mô hình trạng thái của một so sánh: *applicable* (precondition) → *valid pair* → *valid scope* (target đã khai báo, có key) → *verdict available* → *informative* → *satisfied/violated/inconclusive*. "Quan hệ thỏa" và "verdict quan sát được thuộc tính" là hai cột khác nhau; một so sánh thỏa nhưng UNINFORMATIVE không phải bằng chứng về scanner.

## 5. Provenance của mỗi lần chạy

`environment.lock.json` có khối `experiment`: `experiment_id`, `experiment_type` (`baseline | mutation | historical-defect`), `scope_profile`, commit và trạng thái dirty của framework, phiên bản schema, sha256 của catalog / requirements / properties / patterns / mapping / registry, `registry_matches_policy` (registry đã sinh từ đúng policy đang quét hay chưa), `seed_digest`, danh sách MR và status đã chạy. Mỗi case có `provenance.json` (sha256 source/follow-up, digest policy, scanner version, mode, digest mapping+registry).

## 6. Ràng buộc kiến trúc được test

`tests/unit/test_unified_framework.py` kiểm: core không chứa id MR hay id control hardcode; chỉ `runner.py` gọi `scanner.execute` và `check`; không còn `control-inputs`; mọi MR dùng cùng bộ trường; mỗi lỗi nhất quán catalog/mapping/registry ở mục 3 bị `check_mapping` từ chối; một MR mới (MR-10 tạm) chỉ cần catalog + mapping + một class là qua cổng cấu trúc.
