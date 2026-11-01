# Phương pháp dẫn xuất MR cho Kubernetes security scanners (Phase 2)

```
Security Requirement → Security Property → MR Pattern → MR Specification → Executable MR → Evaluation
 (OWASP K8s 2025,        (mrs/security_    (mrs/patterns   (mrs/catalog      (transforms/*.py    (runner +
  CIS, NSA, PSS)          properties.yaml)  .yaml)          .yaml)            @implements)        scanner thật)
```

## 1. Bài học từ MST-wi (đã đọc source)

Nguồn: bài *Metamorphic Testing for Web System Security* (IEEE TSE 2023) và các repo `MST`, `CWE` của
`MetamorphicSecurityTesting` (đã clone và đọc: 87 file `.smrl`, `MR.java`, `Operations.java`, `OperationsProvider.java`).

| MST-wi làm | Áp dụng ở đây |
|---|---|
| Mỗi MR ghi **định nghĩa CWE + "Idea" một câu + chú thích đánh số** | `property_id` trỏ tới `security_properties.yaml` (statement, rationale, nguồn) |
| Thân MR 5–15 dòng nhờ **từ vựng miền dùng chung** (`Operations`) | `k8s.py` + `validation.py` + `transforms/patterns.py` |
| **Provider interface** tách MR khỏi hệ thống được test | Đã có: `scanners/` + `normalize/` |
| **Pattern rút ra sau khi có MR** (23 pattern từ 76 MR) | KP1–KP3 rút từ MR-01..05, không thiết kế trước |
| Giữ **MR bị loại** (`Draft_MRs/*_NO`, `_MayBe`) | Mục `counterexample` bắt buộc; MR chưa kiểm chứng giữ `status: candidate` |

**Không bắt chước:** (1) precondition sai vẫn tính là PASS (trong `OTG_AUTHZ_002.java` nhánh `else` gọi `expressionPass()`),
ở đây là `SKIP/INVALID_PAIR/INCONCLUSIVE/PARTIAL`; (2) `MR.java` 1602 dòng với trạng thái tĩnh toàn cục;
(3) mã hóa danh sách CWE vào tên file. Không xây SMRL compiler: chưa có bằng chứng lợi ích.

MST-wi nhắm CWE của **hệ thống được test**. Ở đây hệ thống được test là **scanner**, nên CWE (nếu có) chỉ mô tả
**loại cấu hình sai mà control phát hiện**, không phải nhãn cho lỗi của scanner.

## 2. Bốn vai trò nguồn, không thay thế nhau

| Vai trò | Nguồn | Dùng để | **Không** dùng để |
|---|---|---|---|
| Chọn miền rủi ro | OWASP K8s Top 10 **2025**, CWE, CIS, NSA/CISA, ATT&CK | Quyết định property nào đáng kiểm | Chứng minh MR đúng |
| Chứng minh ngữ nghĩa | Tài liệu Kubernetes (RBAC, PSS, API) | Lập luận phép biến đổi bảo toàn/thay đổi đúng thuộc tính | |
| Xác định cái gì kiểm được | Tài liệu/mã control đúng phiên bản scanner | `config/control-registry.yaml` (sinh) + `config/policy-mapping.yaml` | Suy diễn từ tên control |
| Dữ liệu đánh giá | KALM, ISSTA benchmark, seed lịch sử/tổng hợp | Input và đánh giá | Chứng minh MR đúng |

Mỗi tham chiếu trong `security_properties.yaml` có cờ `verified`, nghĩa là **đã đối chiếu nguồn gốc của chính tham chiếu đó** (ID/tiêu đề/câu trích khớp), không hơn. Bốn khái niệm tách bạch: `source_verified` (cờ `verified`), `standard_requirement_verified` (chỉ khi đã đọc tài liệu của tiêu chuẩn; hiện chưa có mục nào), `control_mapping_verified` (đọc từ policy đã pin, ghi ở `policy-mapping.yaml` và `MR_CANDIDATE_EVALUATION.md`), `semantic_review_status` (`review_status`). Mục CIS 5.2.5 của SP-POD-HOST-NAMESPACES chỉ là **nhãn trong artifact của Kubescape**, nên là `verified: false` kèm `basis`. NSA/CISA và ATT&CK chưa điền.

OWASP Kubernetes Top 10 2025 (đã kiểm tại kubernetes-top10.owasp.org): K01 Insecure Workload Configurations,
K02 Overly Permissive Authorization Configurations, K03 Secrets Management Failures, K04 Lack Of Cluster Level Policy
Enforcement, K05 Missing Network Segmentation Controls, K06 Overly Exposed Kubernetes Components,
K07 Misconfigured And Vulnerable Cluster Components, K08 Cluster To Cloud Lateral Movement, K09 Broken Authentication
Mechanisms, K10 Inadequate Logging And Monitoring. (ID 2022 khác: RBAC là K03, 2025 là K02.) Việc gán MR vào K01/K02 là
**phán đoán chọn miền**, không phải bằng chứng.

## 3. Quy trình 15 bước (checklist cho MR mới)

| # | Bước | Sản phẩm / nơi ghi |
|---|---|---|
| 1 | Chọn property có cơ sở (hoặc thêm mới) | `security_properties.yaml` |
| 2 | Testing objective: scanner có thể sai ở đâu? | `rationale` |
| 3 | Ngữ nghĩa Kubernetes liên quan | `k8s_spec` (trích nguyên văn, `verified`) |
| 4 | Semantic variation points: cái gì đổi được mà nghĩa không đổi | `scope_assumptions` |
| 5 | Loại quan hệ: invariance / controlled change / predicate riêng | chọn `pattern` |
| 6 | Precondition | `candidates()` + `preconditions` |
| 7 | Transformation | `transform()` |
| 8 | Quan hệ output kỳ vọng | `relation` |
| 9 | Scope control/resource | `targets()` + `policy-mapping.yaml` |
| 10 | Lập luận tính đúng (proof obligation của pattern) | `rationale`, `known_non_equivalences` |
| 11 | Positive example | unit test |
| 12 | **Counterexample** buộc precondition/validator từ chối | `counterexample` + unit test |
| 13 | Gate tự động | `k8s-mr-lab mr validate` |
| 14 | Chạy scanner thật, chỉ khi mapping đã xác minh | `run --mr MR-xx` |
| 15 | Phân loại kết quả, giữ evidence; vi phạm chỉ là *ứng viên*, chưa phải defect | `triage` |

## 4. Catalog pattern (rút từ MR hiện có)

| Pattern | MR | Cấu trúc | Code chung |
|---|---|---|---|
| KP1 representation-invariance | 01, 03 | Viết lại, bất biến giữ nguyên, verdict `equal` | Không (bất biến khác nhau) |
| KP2 noninterference | 02 | Thêm object không với tới được, `equal` | Không (1 thể hiện) |
| KP3 controlled-single-field-change | 04, 05, 06 | Đổi đúng 1 trường, `pass_to_fail`/`fail_to_pass` | `ControlledChange` |

Ví dụ phản biện: MR-03 và MR-01 cùng KP1 nhưng validator khác (permission tuples vs parsed content), nên gộp class sẽ
làm mờ đúng điều cần chứng minh. Chỉ khi xuất hiện MR KP1 thứ ba, nên xét lại.

## 5. Ví dụ theo quy trình mới: MR-06 `host-network-flip`

- Property `SP-POD-HOST-NAMESPACES`: PSS Baseline cấm `spec.hostNetwork: true` (trích nguyên văn, đã xác minh); OWASP K01.
- Pattern KP3, relation `pass_to_fail`. Precondition: `hostNetwork` **có mặt và bằng `false`**.
- Counterexample: pod không khai báo `hostNetwork` không phải candidate; thêm `hostPID` cùng lúc là `INVALID_PAIR`.
- Mapping đọc từ policy bundle đã pin: Trivy KSV-0009, Kubescape C-0041 (không điền theo trí nhớ). Chạy thật trên seed
  `seeds/candidate/pod-hostnet`: cả hai scanner cho PASS (`pass_to_fail`); nguồn Trivy là PASS suy luận, nguồn Kubescape tường minh.
- **Trạng thái `candidate`**: mới có DEV evidence (n=1/scanner). Runner mặc định bỏ qua; chạy bằng `--mr MR-06`. Không có
  tuyên bố nào về khả năng bắt lỗi của MR-06. Chi tiết: `MR_REFACTOR_REPORT.md` §5.
