# Dẫn xuất MR-09 từ yêu cầu R08 (walkthrough end-to-end)

Mục đích: một ví dụ xuyên suốt của quy trình **yêu cầu → MR**, trong đó MR được dẫn xuất từ một câu của tài liệu Kubernetes và từ *hợp đồng* của control, **trước** khi chạy bất kỳ scanner nào.
Mọi thứ trong mục 1–6 được viết trước mục 7 (kết quả). Khác MR-02/05/07, MR-09 không xuất phát từ một hiện tượng đã quan sát của scanner.

## 1. Yêu cầu (nguồn chính thức, trích nguyên văn)

R08, Kubernetes docs, *RBAC Good Practices → Listing secrets* (`https://kubernetes.io/docs/concepts/security/rbac-good-practices/`):

> It is generally clear that allowing `get` access on Secrets will allow a user to read their contents. It is also important to note that `list` and `watch` access also effectively allow for users to reveal the Secret contents.

Nhóm rủi ro: OWASP K8s Top 10 2025 **K02** Overly Permissive Authorization Configurations. Weakness class của cấu hình bị cấm: **CWE-200** *Exposure of Sensitive Information to an Unauthorized Actor* (chọn theo phán đoán; ID/tiêu đề đã kiểm).
OWASP và CWE chỉ chọn miền và phân loại; chúng **không** chứng minh MR đúng.

## 2. Property và biến thể ngữ nghĩa

Property `SP-RBAC-SECRETS-READ-VERBS`: với Secrets, mỗi động từ `get`, `list`, `watch` **đủ** để lộ nội dung; vì vậy một rule chỉ chứa các động từ đọc này cấp cùng một mức *phơi bày Secrets*, bất kể là tập con nào của `{get, list, watch}`.

Điểm biến thiên (semantic variation point): *động từ nào* trong tập đọc. Phép biến đổi giữ nguyên thuộc tính "có thể đọc Secrets" nhưng đổi tập động từ.
Lưu ý: ba động từ **không** tương đương theo nghĩa API (`get` một đối tượng ≠ `list` mọi đối tượng); chúng chỉ tương đương theo thuộc tính *phơi bày nội dung*. Vì vậy quan hệ chỉ đúng với control mà hợp đồng nói về sự phơi bày, không với control đếm động từ.

## 3. Hợp đồng control (đọc từ policy đã pin, chưa chạy gì)

| Control | Hợp đồng đọc được | Phủ get/list/watch? |
|---|---|---|
| Trivy `KSV-0113` "Manage namespace secrets" (`manage_namespace_secrets.rego`) | kind `Role`; cờ khi `resources[_] == "secrets"` **và** `verbs[_]` ∈ `readVerbs := [get, list, watch, create, update, patch, delete, deletecollection, impersonate, *]` | **có**, cả ba |
| Kubescape `C-0015` "List Kubernetes secrets" (`rule-can-list-get-secrets-v1`) | mô tả: "determines which user, group or service account can list/get secrets"; rego `verbs := ["get", "list", "watch", "*"]` | **có**, cả ba (mô tả chỉ nói list/get nhưng rego gồm cả watch) |

Cả hai control đều không đọc `apiGroups` ở phần liên quan (xem N2); MR-09 giữ `apiGroups: [""]` cố định nên không dính vào điều đó.

## 4. MR

* **Precondition:** Role có một rule với `apiGroups == [""]`, `resources == ["secrets"]`, **không** `resourceNames` (với `resourceNames` hành vi của `list`/`watch` khác `get`), và `verbs` là tập con không rỗng của `{get, list, watch}`.
* **Transformation:** thay `verbs` của đúng rule đó bằng **một** động từ `w ∈ {get, list, watch}` khác tập hiện tại.
* **Relation:** `equal` trên control mức Role (`KSV-0113` trên Role; `C-0015` trên Role đã bound).
* **Scope:** chỉ hai control trên, trên đúng Role bị sửa. Không so Role khác (không có).
* **Pattern:** quan hệ `equal` với biến đổi một trường **không** khớp KP1 (viết lại bảo toàn nghĩa API) cũng không KP3 (đổi một chiều); ma trận phần tử cho một tổ hợp mới ⇒ đề xuất **KP4 property-preserving substitution** (giả thuyết, 1 thể hiện).

## 5. Lập luận tính đúng và phản ví dụ

* Từ câu trích: mỗi động từ trong `{get, list, watch}` làm lộ nội dung Secrets ⇒ mức phơi bày của rule không đổi khi thay tập động từ (miễn không rỗng và không thêm động từ ngoài tập đọc).
* Từ hợp đồng control: cả hai control cùng phủ ba động từ ⇒ kỳ vọng `equal` nằm trong phạm vi hợp đồng của chúng.
* Phản ví dụ (đều có test): rule có `resourceNames`; nhiều `resources`; `apiGroups` không phải core; động từ ngoài tập đọc (`create`, `delete`); `verbs: ["*"]`; một Role có hai rule Secrets; follow-up đổi thêm trường khác.
* Giới hạn: tương đương theo *phơi bày* chứ không theo API; control đếm hoặc phân biệt động từ nằm ngoài phạm vi (không được ánh xạ).

## 6. Dự đoán (viết trước khi chạy)

Seed: `rbac-secrets-reader` (Role `lab-c/reader-role`, một rule `secrets`, `verbs: [get, list, watch]`). Các seed khác không có rule Secrets thỏa precondition ⇒ SKIP.
Tham số sinh ra: `{get,list,watch} → [get]`, `→ [list]`, `→ [watch]` (3 cặp).

| Thí nghiệm | Dự đoán |
|---|---|
| Scanner đã pin, Trivy | `KSV-0113` FAIL→FAIL cho cả 3 cặp ⇒ MR `PASS`; so sánh **mang thông tin** (Role bị sửa là chính đối tượng Trivy xét; FAIL gắn resource) |
| Scanner đã pin, Kubescape | `C-0015` FAIL→FAIL cho cả 3 cặp ⇒ `PASS` |
| Mutant `drop-watch-verb` (xóa `"watch"` khỏi `verbs := [...]` của `C-0015`, bản sao cô lập) | cặp `→ [watch]`: `C-0015` FAIL→**PASS** ⇒ **VIOLATION**; cặp `→ [get]` và `→ [list]`: FAIL→FAIL ⇒ không đổi. Mutant được kích hoạt **chỉ** ở cặp `[watch]` |
| Mutant: nguồn | nguồn có `get, list, watch` nên `C-0015` vẫn FAIL ở mutant (không đổi so với pinned) |

**Tính độc lập của thí nghiệm mutant:** mutant được chọn từ *câu trích* ("`watch` cũng làm lộ"), không từ quan sát nào về Kubescape ⇒ không vòng tròn như MR-08. Nhưng vẫn **1 mutant, 1 control, 1 case**: không phải mutation score.
**Kết quả inconclusive nếu:** nguồn `C-0015` ở mutant khác pinned; hoặc scanner đã pin vốn không cho FAIL→FAIL ở nguồn.
Một **VIOLATION ở scanner đã pin** sẽ là phát hiện đáng điều tra (control phân biệt động từ), không tự động là lỗi: phải đối chiếu hợp đồng trước.

## 7. Kết quả (Trivy 0.75.0, Kubescape v4.0.15; evidence: `docs/evidence/mr09_requirement_derived_2026-11-01/`)

Chạy trên 8 seed: 1 `INVALID_SOURCE`, 6 `SKIP` (không có rule Secrets đủ điều kiện), 1 seed áp dụng (`rbac-secrets-reader`) cho 3 cặp.

| Case (`to_verbs`) | Trivy `KSV-0113` | Kubescape pinned `C-0015` | Kubescape mutant `drop-watch-verb` `C-0015` |
|---|---|---|---|
| `[get]` | FAIL → FAIL, **PASS** | FAIL → FAIL, **PASS** | FAIL → FAIL, PASS |
| `[list]` | FAIL → FAIL, **PASS** | FAIL → FAIL, **PASS** | FAIL → FAIL, PASS |
| `[watch]` | FAIL → FAIL, **PASS** | FAIL → FAIL, **PASS** | FAIL → **PASS**, **VIOLATION** |

* **Mọi dự đoán ở mục 6 đúng**, kể cả việc mutant bị kích hoạt *chỉ* ở cặp `[watch]` và nguồn `C-0015` vẫn FAIL ở mutant. Digest policy: pinned `8cfb2323…`, mutant `b40d4d31…` (track riêng).
* **Không có VIOLATION nào ở scanner đã pin:** cả Trivy lẫn Kubescape coi `get`, `list`, `watch` ngang nhau, đúng như hợp đồng và câu trích. MR-09 vì vậy **không tìm ra lỗi mới**; giá trị của nó là kiểm một thuộc tính được tài liệu nêu rõ, và có độ nhạy (giết được mutant).
* **So sánh mang thông tin:** `mr informative` cho Trivy 3/3 và Kubescape 6/6 (pinned + mutant) mang thông tin. Khác MR-02/MR-07 (Trivy 0/40, 0/20): vì MR-09 sửa chính Role mà check Trivy xét.
* **Mutant này không vòng tròn** (được chọn từ câu trích, không từ quan sát về Kubescape), nhưng vẫn là **1 mutant, 1 control, 1 case phân biệt**: không phải mutation score.
* **Độc lập đến đâu:** MR-09 và dự đoán được viết trước khi chạy, nhưng tác giả đã *đọc rego của KSV-0113/C-0015 trước* (mục 3), và điều đó nằm trong quy trình (đọc hợp đồng để xác định phạm vi). Property vẫn `author_reviewed`.
