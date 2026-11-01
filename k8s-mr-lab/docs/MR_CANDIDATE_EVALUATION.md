# Đánh giá các MR ứng viên (candidate)

Ba ứng viên thuộc ba nhóm ngữ nghĩa khác nhau, đánh giá theo 10 câu hỏi. Quy tắc: **không ứng viên nào lên `mvp`/vào run mặc định**
khi thiếu review ngữ nghĩa độc lập và đánh giá không dùng để thiết kế. Theo yêu cầu, chỉ **một** ứng viên (MR-07) được cài đặt;
hai ứng viên còn lại chỉ đặc tả.

| | MR-07 `sa-subject-as-user` | MR-08 `initcontainer-privileged-flip` | MR-09 `sa-token-automount-representation` |
|---|---|---|---|
| Nhóm | RBAC: subject identity / binding scope | workload / container coverage | ServiceAccount token |
| Trạng thái | **cài đặt**, `candidate`, có DEV evidence | **đặc tả, defer** | **đặc tả, defer** |
| Pattern | KP1 (viết lại, `equal`) | KP3 (đổi một trường, `pass_to_fail`) | chưa rõ (xem dưới) |

## MR-07 `sa-subject-as-user` (đã cài đặt)

1. **Property:** `SP-RBAC-SA-SUBJECT-IDENTITY` (hai cách viết cùng danh tính). Trích dẫn đã xác minh (docs Authentication và RBAC).
2. **Ngữ nghĩa tham chiếu:** username của service account là `system:serviceaccount:<ns>:<name>`; subject `User` khớp username đã xác thực.
3. **Control ứng viên (đọc từ policy đã pin):** Trivy KSV-0113/0048/0049/0112/0050 đánh giá **Role** (MR không chạm Role ⇒ Trivy không thể vi phạm: so sánh gần như *rỗng* về subject, ghi nhận như giới hạn); Kubescape C-0267/C-0272 (workload; rego chỉ join `subjects[j].kind == "ServiceAccount"`), C-0015/0007/0035 (Role).
4. **Precondition:** RoleBinding→Role cục bộ; subject `ServiceAccount` có `namespace` tường minh; SA có trong bundle.
5. **Transformation:** thay đúng một subject bằng `{User, apiGroup rbac…, name system:serviceaccount:<ns>:<name>}`.
6. **Relation:** `equal` trên Role-level và workload-level controls.
7. **Counterexample (có test):** Group `system:serviceaccounts:<ns>` (không tương đương); User namespace khác; đổi thêm `roleRef`; thiếu namespace; thiếu SA.
8. **Quan sát được?** Có: verdict tường minh ở Kubescape; Trivy chỉ có PASS suy luận/FAIL gắn Role.
9. **Cần đổi framework?** Không: cài bằng `MetamorphicRelation` + `targets()`; 2 mục catalog/mapping.
10. **Quyết định:** **ACCEPT làm `candidate`**.

**Quan sát thật (DEV, 2026-11-01; Trivy 0.75.0, Kubescape v4.0.15; seed tổng hợp + lịch sử):**

| Scanner | Cặp | PASS | VIOLATION | So sánh ok / violation |
|---|---|---|---|---|
| Trivy | 4 | 4 | 0 | 20 / 0 |
| Kubescape | 4 | 3 | **1** | 17 / **1** |

Violation duy nhất: seed `rbac-secrets-reader`, Kubescape **C-0267 trên `Pod/lab-c/reader-pod`: FAIL → PASS**, verdict tường minh ở cả hai
phía, diff đúng một subject (`ServiceAccount reader` → `User system:serviceaccount:lab-c:reader`). Triage: `CANDIDATE_REPRODUCED`,
`family=kubescape:MR-07:FAIL->PASS`, chưa khớp issue đã biết. Evidence: evidence lịch sử `mr07_dev_2026-11-01` (không còn trong repository; xem `docs/poc/HISTORICAL_DATA.md`).

**Diễn giải (chưa phải kết luận):**
* Phù hợp với rego đã pin: `rolebinding.subjects[j].kind == "ServiceAccount"` nên subject dạng `User` bị bỏ qua ⇒ workload vẫn chạy với quyền đọc Secrets nhưng control ngừng báo (**false negative** nếu control nhằm bao quát mọi cách cấp quyền cho SA).
* Có thể là **giới hạn có chủ đích** (control chỉ định nghĩa trên subject ServiceAccount). Cần đọc mô tả control và hỏi nhà phát triển. Phân loại hiện tại: `UNRESOLVED` (giữa `SCANNER_DEFECT_CANDIDATE` và `POLICY_OR_SCOPE_ISSUE`).
* **Không phải khám phá mù:** MR-07 được viết sau khi đọc rego của C-0267/C-0272. Không dùng làm bằng chứng độc lập.
* n nhỏ: 1 violation trên 1 seed (seed `rbac-secrets-reader` cho Role cấp Secrets); các seed khác có Role vô hại nên C-0267 vốn PASS (không thể thấy FAIL→PASS).

## MR-08 `initcontainer-privileged-flip` (chỉ đặc tả, defer)

1. **Property:** PSS Baseline "Privileged Containers": trường hạn chế gồm `spec.initContainers[*].securityContext.privileged` (trích dẫn đã xác minh).
2. **Ngữ nghĩa:** initContainer là container chạy trước app; `privileged: true` cũng vi phạm.
3. **Control ứng viên:** Trivy KSV-0017 (`privileged.rego` duyệt `keys = {"containers", "initContainers"}`); Kubescape C-0057 (rule tham chiếu `containers`, `ephemeralContainers`, `initContainers`). Cả hai *có vẻ* bao quát initContainers (đọc mã, chưa chạy).
4. **Precondition:** workload có `initContainers[i].securityContext.privileged: false` tường minh.
5. **Transformation:** đặt `privileged: true` trên đúng một initContainer.
6. **Relation:** `pass_to_fail` trên KSV-0017 / C-0057.
7. **Counterexample:** chỉ sửa container thường (phải bị `ControlledChange` từ chối vì path khác); sửa hai initContainer; nguồn đã FAIL.
8. **Quan sát được?** Dự kiến có; chưa chạy.
9. **Cần đổi framework?** Gần như không: `iter_containers` hiện chỉ trả container thường ⇒ cần helper cho `initContainers` (một hàm).
10. **Quyết định:** **DEFER**. Cấu trúc gần như trùng MR-04 (cùng KP3, khác danh sách container): thêm vào lúc này làm tăng số MR mà ít thêm thông tin; chỉ đáng làm nếu thầy muốn kiểm tính phủ container, và cần seed có initContainer (chưa có).

## MR-09 `sa-token-automount-representation` (chỉ đặc tả, defer)

1. **Property (dự kiến):** hai cách khai báo cùng ý nghĩa mount token (`automountServiceAccountToken` ở Pod vs ở ServiceAccount) cho cùng hiệu lực.
2. **Ngữ nghĩa tham chiếu:** cần xác minh nguyên văn: trường ở Pod ưu tiên hơn trường ở ServiceAccount; mặc định khi cả hai vắng; projected volume tường minh. **Chưa xác minh** (không trích dẫn nào được lấy).
3. **Control ứng viên (đọc metadata):** Trivy `protecting_pod_service_account_tokens.rego`; Kubescape C-0034 (`automount-service-account`), C-0261, C-0189. Hơn nữa C-0267/C-0272 tự tính `is_sa_auto_mounted(wl_spec, sa)` trong rego ⇒ tương tác với MR-02/MR-07.
4–6. Precondition/transformation/relation **chưa chốt**: biến đổi "tương đương" duy nhất chắc chắn là chuyển giá trị giữa Pod và SA khi không có giá trị mâu thuẫn; việc đó phụ thuộc quy tắc ưu tiên chưa xác minh.
7. **Counterexample:** Pod đặt `true`, SA đặt `false` (Pod thắng); cả hai vắng (mặc định runtime).
8. **Quan sát được?** Chưa biết.
9. **Cần đổi framework?** Có thể: cần mô hình defaulting, vượt khả năng hiện tại của `ConfigBundle`.
10. **Quyết định:** **DEFER**, điều kiện mở lại: trích dẫn ngữ nghĩa ưu tiên đã xác minh + một seed có đủ trường hợp. Không đưa vào mã.

## Tóm tắt quyết định

| MR | Quyết định | Lý do chính |
|---|---|---|
| MR-06 | giữ `candidate` | DEV n=1/scanner, PASS suy luận ở Trivy |
| MR-07 | accept `candidate` | có cơ sở ngữ nghĩa đã trích dẫn, counterexample, evidence thật; **dẫn dắt**, n nhỏ |
| MR-08 | defer | gần trùng MR-04, cần seed |
| MR-09 | defer | ngữ nghĩa defaulting chưa xác minh |

## MR-07: đánh giá lại ngày 2026-11-01 (7 câu hỏi)

Nguồn: policy đã pin (`c-0267.json`, `c-0272.json`, `c-0015.json`, `c-0035.json`; rego của Trivy), `config/control-registry.yaml`, `mr informative`.

| # | Câu hỏi | Trả lời có căn cứ |
|---|---|---|
| 1 | Ngữ nghĩa K8s có coi hai biểu diễn là cùng danh tính không? | **Có, với một bước suy diễn.** Đã trích nguyên văn: username của service account là `system:serviceaccount:(NS):(SA)` (docs Authentication) và "ServiceAccounts have names prefixed with `system:serviceaccount:`" (docs RBAC). Bước "subject `User` khớp username đã xác thực" là cách RBAC hoạt động nhưng **không có câu trích riêng** trong hai trang đã đọc: ghi `verified: false` cho bước đó nếu cần chặt hơn |
| 2 | Precondition đủ chưa? | Đủ cho `equal` ở mức hiện tại: RoleBinding→Role cục bộ, subject SA có namespace tường minh, SA có trong bundle. Không cần "không có binding khác" vì một subject bị viết lại không làm thêm/bớt đường nào khác |
| 3 | Counterexamples | Group `system:serviceaccounts:<ns>` (rộng hơn); User namespace khác; đổi thêm `roleRef`; thiếu namespace; thiếu SA (5 test) |
| 4 | Control nào thật sự quan sát danh tính subject? | **Kubescape `C-0267`/`C-0272`** (join `subjects[j].kind == "ServiceAccount"`, `.name`, `.namespace` trên `RoleBinding`). `C-0015/C-0007/C-0035` dùng aggregator `subjectVector` (mô tả: "user, group or service account"); đã ánh xạ ở mức **Role**, không phải mức workload. **Trivy: không có.** |
| 5 | PASS của Trivy có mang thông tin không? | **Không.** Các check Trivy được ánh xạ (KSV-0113/0048/0049/0112/0050) có `selector kind: role`, nhận **một tài liệu Role** mỗi lần; MR-07 chỉ sửa RoleBinding. `mr informative`: **0/20 so sánh mang thông tin** (20 UNINFORMATIVE). ⇒ **đã bỏ ánh xạ Trivy cho MR-07** (xem dưới) |
| 6 | Hợp đồng `C-0267` có hỗ trợ subject `User` không? | Mô tả: "workload ... **service accounts** have roles that ..."; remediation: "Make sure each **service account** has only the permissions...". Rego chỉ join `kind == "ServiceAccount"`. Lời văn của hợp đồng nói về **quyền của service account mà workload dùng**, điều mà dạng `User` cũng mang lại; còn cài đặt hẹp hơn lời văn. **Không đủ để kết luận lỗi hay chủ ý** |
| 7 | Quan sát Kubescape: ngoài phạm vi chính sách hay ứng viên lỗi? | **`UNRESOLVED`.** H1 *giới hạn chủ ý*: control chỉ định nghĩa trên subject `ServiceAccount`. H2 *false negative*: hợp đồng nói về quyền của SA, mà dạng `User` cấp cùng quyền đó. Chưa có tài liệu control hoặc phản hồi upstream để phân xử |

**Thay đổi đã làm:** bỏ mục `trivy` của MR-07 khỏi `config/policy-mapping.yaml`. Lý do là cấu trúc (control không đọc đối tượng bị đổi), không phải kết quả. Evidence cũ evidence lịch sử `mr07_dev_2026-11-01` (không còn trong repository; xem `docs/poc/HISTORICAL_DATA.md`) giữ nguyên làm bằng chứng lịch sử.
**Không** nâng trạng thái MR-07; **không** gọi kết quả Kubescape là false negative.
