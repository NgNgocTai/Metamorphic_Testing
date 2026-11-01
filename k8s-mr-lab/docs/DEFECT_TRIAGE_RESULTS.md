# Hồ sơ triage hai ứng viên lỗi (cho người nghiên cứu tự adjudicate)

Trạng thái cả hai: **`READY_FOR_HUMAN_ADJUDICATION`**. Không có mục nào được đánh `CONFIRMED` hay `NEW DEFECT`.
Môi trường: Trivy 0.75.0 (checks bundle `sha256:b591e919…`), Kubescape v4.0.15 (artifacts digest `8cfb2323…`), cả hai local-file mode.
Bằng chứng gốc: `runs/{kubescape,trivy}/reproducers/*` (mỗi gói tự chứa source, follow-up, diff, raw JSON, `reproduce.sh`), `docs/evidence/*.json` (ablation do `scripts/triage_probe.py` sinh ra) và `runs/evidence-pack.zip`. Thư mục `runs/*/cases/` (artifact từng case) đã được dọn; chạy lại `scripts/demo.sh` sẽ sinh lại chúng.

Quy trình triage: chạy lại cặp trên cùng phiên bản (`k8s_mr_lab triage`), tạo gói reproducer, ghi bằng chứng rule và ablation; **không bao giờ tự gắn `CONFIRMED`**. Kết luận cuối do người nghiên cứu đọc bằng chứng và quyết định (xem `HUONG_DAN_TU_KIEM_TRA.md`).

## 0. Phân biệt ba mức kết luận

| Mức | Nghĩa | Hiện có |
|---|---|---|
| **MR violation** (alert) | quan hệ MR không thỏa trên một cặp hợp lệ | 6 dòng alert = 4 cặp input duy nhất (Kubescape 5 dòng / 3 cặp duy nhất; Trivy 1 / 1) |
| **Scanner defect candidate** | violation đã tái hiện, đã loại trừ lỗi framework/MR, có giả thuyết nguyên nhân gốc | 2 họ: K1 (Kubescape) và N2 (Trivy) |
| **Confirmed defect** | người nghiên cứu đã đọc bằng chứng và kết luận | **0** — chờ bạn |

Khử trùng: seed `K1-role-namespace` trùng hệt `rbac-workload`, nên 5 alert Kubescape chỉ là 3 input khác nhau
(`rbac-workload`/`K1` × {secrets_read, wildcard_admin} và `rbac-secrets-reader` × wildcard_admin) thuộc một họ nguyên nhân.

---

## 1. Kubescape v4.0.15 — MR-02, lớp K1

**Hiện tượng.** Thêm Role `app-role` (không bind) vào namespace `lab-a-decoy`: `C-0267` của Deployment `lab-a/web` đổi `passed → failed`
(profile `secrets_read`); với `wildcard_admin`, cả `C-0267` và `C-0272` đổi. RoleBinding `lab-a/app-binding` và Role `lab-a/app-role` không đổi một ký tự.

| Bước | Kết quả |
|---|---|
| 1. Chạy lại reproducer, đúng version/policy pin | `bash runs/kubescape/reproducers/*/reproduce.sh` in `source C-0272 passed` / `followup C-0272 failed`; `triage` rerun cho cùng tập violation (`CANDIDATE_REPRODUCED`) |
| 2. Kiểm manifest | diff chỉ là một Role mới (`diff.patch`); `trace.json` ghi thao tác `rbac.add_unbound_same_name_role` |
| 3. Tiền điều kiện/tính hợp lệ MR-02 | pair validator: đúng 1 object thêm, 0 binding thêm, namespace decoy mới và chỉ chứa Role đó. Ngữ nghĩa K8s: RoleBinding phân giải `roleRef` Role chỉ trong namespace của nó, nên `lab-a:app` không nhận quyền của Role ở `lab-a-decoy` |
| 4. Raw JSON | `scanner-followup.json`: control `C-0267` của Deployment `web` có `status: failed`, rule `workload-with-cluster-takeover-roles`. **Kubescape tự liệt kê `.../lab-a-decoy/Role/app-role` trong `relatedResourcesIDs` của alert** — tức scanner dùng chính Role decoy làm căn cứ cảnh báo |
| 5. Rego | xem bên dưới |
| 6. So với issue #2579 | xem bên dưới |
| 7. Loại trừ lỗi normalizer/mapping/scope | xem bên dưới |

**Cơ chế (rego, artifacts đã pin).**
`c-0267.json` L20–27: `role := input[_]` (mọi Role/ClusterRole trong input) rồi `rolebinding.roleRef.name == role.metadata.name` và `rolebinding.roleRef.kind == role.kind`;
không có phép so `role.metadata.namespace` với namespace của binding. `c-0272.json` L21–27 tương tự và còn **không so cả `roleRef.kind`**.
Vì vậy mọi Role cùng tên, ở bất kỳ namespace nào, được coi là Role mà binding trỏ tới.

**Ablation (`docs/evidence/k1_kubescape_ablation.json`)** — mỗi biến thể chỉ khác baseline một điểm:

| Biến thể | C-0267 | Kết luận rút ra |
|---|---|---|
| A. baseline, không decoy | PASS | nền hợp lệ |
| B. decoy cùng tên, quyền secrets (ứng viên) | **FAIL** | tái hiện |
| C. decoy cùng tên, quyền vô hại (configmaps) | PASS | kích hoạt do quyền của Role decoy |
| D. decoy **khác tên**, quyền secrets | PASS | kích hoạt do trùng **tên** |
| E. Role secrets không bind, **cùng namespace**, khác tên | PASS | Role không bind thì vô hại; không phải "thêm bất kỳ Role nào" |
| F. đối chứng dương: chính Role local cấp secrets | **FAIL** (và `C-0015` FAIL) | control hoạt động đúng khi quyền thật sự được cấp |

**Loại trừ.** *Normalizer:* kết luận dựa trên `status` thô trong raw JSON (đã đọc ở bước 4), resource target là Deployment `web` có `resourceID` xác định.
*Mapping/scope:* `C-0267/C-0272` là control cấp workload và đúng là control cam kết "workload có role takeover/administrative"; mapping MR-02 cho chúng target `workload`, không trộn finding của Role decoy.
*MR áp dụng sai:* không — F cho thấy nếu quyền thật sự được cấp thì FAIL là đúng; trong B không có binding nào tới Role decoy.

**Đề xuất kết luận (để bạn xem xét):** *scanner defect — false positive trong rego của `C-0267`/`C-0272` do ghép Role–RoleBinding theo tên, bỏ qua namespace* (mức độ: Medium theo severity của control).

**Quan hệ với issue kubescape/kubescape#2579** (đã đọc thân issue qua GitHub API ngày 2026-10-29: tạo 2026-07-29, trạng thái *closed*).
Issue mô tả lỗi trong hàm Go `AggregateResourcesBySubjects` (`reporthandling/regoresourcesaggregator.go`, repo `kubescape/opa-utils`), nơi ghép binding/role theo `roleRef.kind + name`.
Quan sát trên v4.0.15: các control đi qua aggregator (`C-0015`, `C-0007`, `C-0035`, `C-0053`: `ok` trong cả 8/8 cặp MR-02, theo `runs/kubescape/comparisons.csv`) **không** bị ảnh hưởng, trong khi `C-0267/C-0272` tự join trên input thô
(`role := input[_]`, không dùng `subjectVector`). Do đó **cùng lớp lỗi (ghép roleRef theo tên, bỏ qua namespace), nhưng không có bằng chứng cùng nguyên nhân gốc/cùng vị trí mã**.
Chưa xác minh: commit sửa nào đóng #2579 và nó đã nằm trong v4.0.15 chưa. Vì issue đã tồn tại, **không gọi đây là lỗi mới**; chỉ có thể là *lỗi chưa được báo ở rule `C-0267/C-0272`* nếu tìm không thấy issue khác.

**Việc còn lại cho bạn:** (a) tìm trong issue/PR của kubescape xem `C-0267/C-0272` đã được báo hoặc sửa chưa; (b) thử v4.0.16/4.0.17 (có sẵn ở `D:\Code\KLTN\Tools`) để biết lỗi còn không; (c) tự chạy lại `reproduce.sh`; (d) quyết định `CONFIRMED` hay không.

---

## 2. Trivy 0.75.0 — MR-05, lớp N2

**Hiện tượng.** Role `lab-c/reader-role` chỉ có một rule (`apiGroups: [""]`, `resources: [secrets]`, verbs get/list/watch): `KSV-0113` **FAIL**.
Đổi duy nhất `apiGroups: [""]` → `["apps"]`: `KSV-0113` vẫn **FAIL**. Quan hệ MR-05 (`fail_to_pass`) bị vi phạm.

| Bước | Kết quả |
|---|---|
| 1. Chạy lại reproducer | `reproduce.sh` in `source KSV-0113 FAIL …` và `followup KSV-0113 FAIL …`; rerun trong `triage` tái hiện |
| 2. Chỉ quyền liên quan đổi | `diff.json` có đúng một thay đổi: `rules[0].apiGroups[0]: "" → "apps"` (validator MR-05 kiểm tra điều này) |
| 3. Không Role/Binding khác cấp cùng quyền | precondition MR-05: Role chỉ có **một** rule; trong seed không còn Role nào khác ngoài `reader-role`; ablation `assert` mỗi biến thể có đúng 1 rule |
| 4. Rego | `manage_namespace_secrets.rego` L34–39: `input.rules[ru].resources[r] == "secrets"` và verb ∈ danh sách; **không có chữ `apiGroups` nào trong tệp** |
| 5. Control cam kết gì | `Manage namespace secrets` — "Viewing secrets at the namespace scope can lead to escalation…", khuyến nghị "Remove resource 'secrets' from role", áp dụng cho `kind: role` |
| 6. Raw JSON + normalizer | `scanner-followup.json` có entry `KSV-0113 FAIL` với `StartLine` nằm trong tài liệu `Role reader-role`; FAIL được gắn vào Role bằng ánh xạ dòng → khớp thông báo "Role 'reader-role' … namespace 'lab-c'" |
| 7. Không do suy luận PASS / ngoài scope | **Không dùng PASS suy luận**: cả hai phía đều là *FAIL có gắn resource* (bằng chứng dương). Control `KSV-0113` nằm trong phạm vi MR-05 vì cam kết phát hiện quyền trên `secrets` |

**Ablation (`docs/evidence/n2_trivy_ablation.json`):**

| Biến thể (Role có đúng 1 rule) | Trivy KSV-0113 | Kubescape C-0015 (đối chiếu) |
|---|---|---|
| A. `apiGroups: [""]`, secrets | FAIL | FAIL |
| B. `apiGroups: ["apps"]`, secrets (ứng viên) | **FAIL** | PASS |
| C. `apiGroups: ["no-such-group.example.com"]`, secrets | **FAIL** | PASS |
| D. `apiGroups: ["apps"]`, `deployments` | PASS | PASS |

Check phân biệt được *resource* (D PASS) nhưng không phân biệt *API group* (B, C FAIL). Kubescape cùng cặp xử lý đúng. Lưu ý đây là đối chiếu chéo (`CROSS_SCANNER_OBSERVATION`), không phải oracle.

**Mở rộng của cùng một họ:** trong rego đã pin, `KSV-0048/0049/0050/0056/0112/0113` đều không chứa `apiGroups`; `KSV-0044` có. MR-05 mới chạm `KSV-0113` (Role chỉ-secrets). `KSV-0041` chỉ áp dụng ClusterRole nên không xuất hiện khi quét Role. Chưa kiểm các check còn lại → chỉ gộp thành **một họ nguyên nhân giả định**, chưa phải khẳng định.

**Đề xuất kết luận (để bạn xem xét):** *scanner defect mức thấp — false positive*: một Role chỉ cấp "secrets" trong API group `apps` không cấp quyền nào lên Secrets (Secrets thuộc core group), nhưng `KSV-0113` báo như có.
Điểm cần bạn cân nhắc: (i) nhà phát triển có thể xem đây là lựa chọn thiết kế "cảnh báo mọi rule nhắc `secrets`"; nếu vậy cần đối chiếu mô tả check; (ii) một bản sửa đúng phải coi `""` và `"*"` đều là core (wildcard group khớp core), không chỉ so chuỗi rỗng.

**Việc còn lại cho bạn:** đọc mô tả check trên trang AVD/Trivy docs, tìm issue upstream (chưa kiểm tra), thử Trivy 0.76.1 (có ở `D:\Code\KLTN\Tools`), tự adjudicate.

---

## 3. Những gì KHÔNG được suy ra từ hai ứng viên này

* Không phải blind discovery: MR-02 viết sau khi biết K1; MR-05 viết sau khi biết N2 (guided/regression).
* Không có số "alert precision" hay "specificity": chưa có adjudication thủ công và chưa có negative case gán nhãn độc lập.
* 6 dòng alert ≠ 6 bug; 4 input duy nhất; 2 họ nguyên nhân giả định; 0 confirmed.

---

## 4. Chạy lại 2026-11-01 (không đổi kết luận) và hiện tượng mới

* Chạy lại `triage --minimize` và `scripts/triage_probe.py` trên Trivy 0.75.0 / Kubescape v4.0.15 đã pin, trong bản sao cô lập của cây đã commit: trạng thái / họ / `known_issue` của cả 6 alert **giống hệt**; hai tệp ablation **giống hệt byte** bản đã commit. Evidence: `docs/evidence/p0_reverification_2026-11-01/`. K1/N2 vẫn là candidate, **0 confirmed**.
* Phân loại theo thang của `KNOWN_DEFECT_EVALUATION_PLAN.md §2`: K1, N2 = `SCANNER_DEFECT_CANDIDATE` (chờ adjudication); chưa có mục `CONFIRMED_SCANNER_DEFECT`.
* **Hiện tượng mới, `UNRESOLVED`:** MR-07 (candidate) trên Kubescape: `C-0267` `Pod/lab-c/reader-pod` FAIL → PASS khi subject `ServiceAccount reader` được viết lại thành `User system:serviceaccount:lab-c:reader`. Rego đã pin chỉ join `subjects[j].kind == "ServiceAccount"`, nên có thể là giới hạn có chủ đích (`POLICY_OR_SCOPE_ISSUE`) hoặc false negative. MR-07 được viết sau khi đọc rego này (dẫn dắt). Evidence: `docs/evidence/mr07_dev_2026-11-01/`; phân tích: `docs/MR_CANDIDATE_EVALUATION.md`.
* **Thí nghiệm vá/đột biến (Kubescape, bản sao artifacts cô lập):** vá `C-0267` bằng so sánh namespace khiến 4 violation của C-0267 biến mất, 3 của C-0272 còn nguyên; mutant bỏ so sánh namespace của subject sống sót qua cả bộ MR (46/46 case). Bản vá là của tác giả, **không** phải bản sửa upstream. Xem `docs/EVALUATION_PROTOCOL_V2.md §5`.
