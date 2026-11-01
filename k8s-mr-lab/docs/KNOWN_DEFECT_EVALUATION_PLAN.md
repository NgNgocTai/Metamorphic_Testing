# Kế hoạch đánh giá trên lỗi scanner đã biết (known-defect evaluation)

**Trạng thái: kế hoạch. Số mục đủ điều kiện hiện tại = 0, nên không có tỉ lệ phát hiện nào được tính hay được phép tuyên bố.**
Tài liệu này không liệt kê issue nào ngoài những gì đã được đọc trong repository; mọi issue khác cần khảo sát trước (xem §3).

## 1. Điều đã có và điều chưa có

| Mục | Phân vùng | Ghi chú |
|---|---|---|
| K1 (Kubescape C-0267/C-0272, join Role theo tên) | DEV/REGRESSION | MR-02 viết **sau** K1; liên hệ `kubescape#2579` (đã đọc 2026-10-29: tạo 2026-07-29, *closed*). Cùng lớp lỗi, **chưa chứng minh cùng nguyên nhân** (control tự join trên input thô, không qua aggregator của issue) |
| N2 (Trivy KSV-0113 bỏ qua `apiGroups`) | DEV/REGRESSION | MR-05 viết sau N2; chưa tra issue upstream |
| MR-07: Kubescape C-0267 FAIL→PASS khi subject viết dạng User | DEV | `UNRESOLVED` (có thể là giới hạn có chủ đích); không phải known defect |
| Bản vá giả định `namespace-fix` | công cụ | không phải bản vá upstream, không dùng làm ground truth |

K1 và N2 **không** vào mẫu số độc lập vì đã dẫn dắt thiết kế MR.

## 2. Trạng thái phân loại một hiện tượng (dùng trong báo cáo; chưa thêm vào mã)

`UNINVESTIGATED → REPRODUCED → { FRAMEWORK_ISSUE | POLICY_OR_SCOPE_ISSUE | SCANNER_DEFECT_CANDIDATE | UNRESOLVED } → CONFIRMED_SCANNER_DEFECT`

Mã hiện dùng `CANDIDATE_REPRODUCED` (triage) và `READY_FOR_HUMAN_ADJUDICATION` (hồ sơ). Chỉ người nghiên cứu sau khi đọc bằng chứng
mới được chuyển sang `CONFIRMED_*`. Ánh xạ: `CANDIDATE_REPRODUCED` ≈ `REPRODUCED`/`SCANNER_DEFECT_CANDIDATE` tùy hồ sơ; thêm trạng thái vào mã
khi có ≥1 hiện tượng cần phân biệt `POLICY_OR_SCOPE_ISSUE` (MR-07 là ứng viên đầu tiên) để không phá `triage.json` hiện có.

## 3. Quy trình khảo sát (đề xuất)

1. Tra Issues/PR/release notes của Trivy, `trivy-checks`, Kubescape và `opa-utils` theo từ khóa có phạm vi (RBAC, roleRef, namespace, apiGroup, initContainers, false positive/negative). Ghi URL, ngày, trạng thái.
2. Với mỗi mục: `LEAD → SOURCE_VERIFIED → REPRODUCIBLE → ELIGIBLE_FROZEN → ADJUDICATED`. Issue đóng không chứng minh bug; issue mở không chứng minh bug.
3. Loại: lỗi build/CLI, CVE phụ thuộc, lỗi chỉ ở chế độ live-cluster nếu đánh giá là static.
4. Gom nhiều issue cùng nguyên nhân thành **một** lỗi (đơn vị đếm = họ nguyên nhân đã adjudicate).
5. Với mỗi mục đủ điều kiện, ghi: scanner, component, phiên bản lỗi, phiên bản sửa (chỉ khi xác minh được), control, reproducer tối thiểu, mode, policy digest, MR có khả năng phát hiện, hành vi quan sát kỳ vọng, trạng thái tái hiện.

Schema bản ghi (đề xuất): `id, scanner, component, source{issue_url, fix_pr_url, evidence_type}, versions{buggy, fixed, policy_digest}, reproducer{bundle_path, property, scan_mode}, selection{partition, used_in_mr_design, eligible_for_eval, reason}, adjudication{status, reviewer}`.

## 4. Chỉ số và mẫu số

* **Eligibility** chốt trước khi xem kết quả MT, **theo property/control/phiên bản/mode**, không theo việc MR hiện có kích hoạt được lỗi. Ghi riêng `exercised_by_suite` và `detected_by_suite`; lỗi thuộc phạm vi mà không được kích hoạt vẫn nằm trong mẫu số (một miss).
* `Known-defect detection = detected eligible distinct defects / all eligible distinct defects`. Báo `k/n`; nếu `n` nhỏ, báo từng ca (case study), không phần trăm.
* Phát hiện *trên bản lỗi* và *hết trên bản đã sửa* (nếu có đủ hai binary): bằng chứng mạnh hơn một phía.
* Không báo specificity/false-alarm rate khi chưa có tập negative có ground truth.
* Mutation (§5 của `EVALUATION_PROTOCOL_V2.md`) báo **bảng riêng**; không trộn với lỗi thật.

## 5. Cổng quyết định

* Gate A (tài liệu): catalog + log chọn/loại có nguồn: làm được không cần mã.
* Gate B: ≥1 lỗi độc lập có bản lỗi, tái hiện và adjudication trước khi nói "đo trên lỗi thật".
* Gate C: chỉ báo tỉ lệ khi mẫu số đã chốt và đủ lớn; nếu không, báo case study + applicability + mutation.
* Gate D: bảng `confirmed/dismissed/unresolved` tính lại được từ raw artifacts.

## 6. Việc thực hiện sớm nhất có giá trị (không cần quyết định thêm)

* Kiểm K1 và N2 trên Kubescape v4.0.16/v4.0.17 và Trivy 0.76.1 (binary sẵn ở `D:\Code\KLTN\Tools`): một **track thí nghiệm riêng** (digest khác), cho biết lỗi còn hay đã hết ở bản mới: không đổi baseline.
* Tra `kubescape` và `trivy-checks` xem `C-0267/C-0272` và `KSV-0113` (apiGroups) đã được báo hay sửa chưa.
