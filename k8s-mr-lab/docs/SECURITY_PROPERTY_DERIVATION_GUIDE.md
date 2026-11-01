# Hướng dẫn dẫn xuất một MR từ security property (ví dụ làm thật: MR-07)

Chuỗi: **requirement → property → Kubernetes semantics → variation points → MR → precondition → transformation →
relation → scope → proof obligations → ví dụ/phản ví dụ → cài đặt → kiểm chứng → đánh giá.**
Với mỗi bước: input, cơ sở, output, tiêu chí đúng/sai, phần tự động, phần phải review tay, nơi dễ báo giả do thiết kế sai.

## Bảng 14 bước

| # | Bước | Input | Cơ sở | Output | Tiêu chí | Tự động? | Review tay | Dễ sai ở đâu |
|---|---|---|---|---|---|---|---|---|
| 1 | Chọn requirement | OWASP K8s 2025, CIS, PSS, CWE | tài liệu rủi ro | miền nghiên cứu (ví dụ K02) | miền có control quan sát được | không | có | chọn miền mà scanner không có control |
| 2 | Phát biểu property | miền + tài liệu K8s | trích dẫn nguyên văn | mục trong `security_properties.yaml` | mọi tham chiếu `verified` | schema (`mr validate`) | **có**: đối chiếu trích dẫn | phát biểu rộng hơn trích dẫn |
| 3 | Ngữ nghĩa K8s | property | docs, API | `k8s_objects`, `scope_assumptions` | xác định được object nào liên quan | không | có | bỏ sót defaulting, ClusterRole, wildcard |
| 4 | Variation points | ngữ nghĩa | tìm *cách viết khác nhau của cùng nghĩa* hoặc *đổi một thuộc tính* | danh sách biến đổi ứng viên | mỗi biến đổi có nghĩa xác định | không | có | biến đổi tưởng bảo toàn nghĩa nhưng không (CE trong case study) |
| 5 | Loại quan hệ | biến đổi | invariance / controlled change / predicate | chọn `pattern` KP1–KP3 | phù hợp `allowed_relations` | `mr validate` | có | gán pattern theo hình thức thay vì lý do |
| 6 | Precondition | property | cấu trúc object | `applicable` + `preconditions` | loại được counterexample | test | có | precondition lỏng ⇒ báo giả |
| 7 | Transformation | biến đổi | | `transform` | không sửa source, xác định | `mr validate` | có | thay đổi ngoài ý |
| 8 | Relation + scope | control scanner | metadata control | `relation`, `targets`, `policy-mapping.yaml` | control **thật sự cam kết** property | không | **bắt buộc**: đọc rego/metadata đúng phiên bản | so cả finding hợp lệ trên object mới |
| 9 | Proof obligation | 1–8 | pattern.`proof_obligation` | lập luận ngắn trong `rationale` + case study | không còn đường quyền khác (closed bundle) | không | **bắt buộc** | quyền cấp qua đường khác |
| 10 | Ví dụ + phản ví dụ | | | test dương/âm | validator/precondition từ chối phản ví dụ | test | có | phản ví dụ chỉ người mới thấy được |
| 11 | Cài đặt | | `mr scaffold` | class `@implements` | | một phần | | |
| 12 | Cổng cấu trúc | | `mr validate` | 0 error | | có | | **không** chứng minh ngữ nghĩa |
| 13 | Chạy thật (DEV) | seed phát triển | scanner đã pin | `comparisons.csv`, evidence | đọc `comparisons.csv` | có | có | n nhỏ |
| 14 | Đánh giá độc lập | tập chưa dùng thiết kế | `EVALUATION_PROTOCOL_V2.md` | kết quả đóng băng | không sửa MR sau khi xem | có | có | rò rỉ dữ liệu |

## Ví dụ làm thật: MR-07 `sa-subject-as-user`

1. **Requirement:** OWASP K8s 2025 **K02 Overly Permissive Authorization Configurations** (đã xác minh tại kubernetes-top10.owasp.org). Chỉ chọn miền.
2. **Property** `SP-RBAC-SA-SUBJECT-IDENTITY`: subject `{ServiceAccount, N, S}` và `{User, system:serviceaccount:S:N}` cùng danh tính.
   Trích dẫn đã xác minh: "Service accounts authenticate with the username `system:serviceaccount:(NAMESPACE):(SERVICEACCOUNT)`…" (docs Authentication) và "`system:serviceaccount:` (singular) is the prefix for service account usernames" (docs RBAC).
3. **Ngữ nghĩa:** RBAC khớp subject `User` với username đã xác thực, nên hai cách viết cấp Role cho cùng danh tính.
4. **Variation point:** cách *viết* subject (ServiceAccount vs User). Không phải mọi cách viết tương đương: `Group system:serviceaccounts:S` phủ **mọi** SA của namespace ⇒ **không** tương đương (đưa vào counterexample).
5. **Loại quan hệ:** viết lại bảo toàn nghĩa ⇒ KP1, `equal`.
6. **Precondition:** RoleBinding → Role cục bộ; subject `ServiceAccount` có `namespace` **tường minh** (không dựa vào defaulting) và SA có trong bundle.
7. **Transformation:** thay đúng một subject.
8. **Scope:** control cấp Role trên Role đích (không đổi) và control cấp workload trên workload dùng SA đó.
9. **Proof obligation:** lập luận bước 3, và *quan trọng*: không đường quyền nào khác thay đổi (chỉ đổi một subject).
10. **Phản ví dụ có test:** subject Group; User với namespace khác; RoleBinding đổi thêm `roleRef`; subject thiếu `namespace`; SA không có trong bundle (`tests/unit/test_mrs.py::test_mr07_*`).
11–12. Cài đặt `transforms/rbac_sa_subject_as_user.py`; `mr validate` 0 error.
13. **Chạy thật (DEV, 2026-11-01):** xem `docs/MR_CANDIDATE_EVALUATION.md §MR-07` và `docs/evidence/archive/mr07_dev_2026-11-01/`.
14. Chưa có đánh giá độc lập; MR-07 giữ `candidate`.

**Lưu ý trung thực:** MR-07 được thiết kế *sau khi đọc* rego của `C-0267/C-0272` (join chỉ cho `subjects[j].kind == "ServiceAccount"`),
nên là MR dẫn dắt bởi kiến thức về scanner, không phải khám phá mù. Cách thiết kế tốt hơn là xuất phát từ property rồi *mới* đọc control; điều này được ghi nhận như một giới hạn.
