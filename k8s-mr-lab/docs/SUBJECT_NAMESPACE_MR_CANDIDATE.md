# MR-08 `sa-subject-namespace-shift` (candidate): subject namespace là một phần của danh tính

## 1. Property

`SP-RBAC-SA-SUBJECT-NAMESPACE`: một subject `{kind: ServiceAccount, name: N, namespace: S}` chỉ chỉ tới ServiceAccount `N` **trong namespace S**.
Hai ServiceAccount cùng tên ở hai namespace khác nhau là hai danh tính khác nhau; một binding cho `S1:N` không cấp quyền cho `S2:N`.

Nguồn đã xác minh: tài liệu RBAC, mục *Referring to subjects*, ví dụ subject `ServiceAccount` luôn kèm `namespace`; tài liệu Authentication: username
`system:serviceaccount:(NAMESPACE):(SERVICEACCOUNT)` (namespace nằm trong tên). Hai trích dẫn này đã được kiểm ở `mrs/security_properties.yaml`
(`SP-RBAC-SA-SUBJECT-IDENTITY`); property mới dựa vào cùng nguồn, **suy diễn** thêm rằng namespace phân biệt danh tính; không có câu trích riêng
nói "binding cho S1:N không cấp cho S2:N" (đây là hệ quả, ghi `verified: false` cho mệnh đề suy diễn ấy).

## 2. Vì sao không phải "chỉ cần thêm hai SA trùng tên"

Thêm một ServiceAccount cùng tên ở namespace khác (kèm workload dùng nó) **không** tạo ra phép so sánh có nghĩa với relation hiện có
(`equal`, `pass_to_fail`, `fail_to_pass` so sánh *cùng một* `(control, resource)` trước và sau): workload mới không tồn tại ở nguồn, nên không có verdict nguồn.
Còn nếu chỉ kiểm workload cũ thì lỗi "bỏ qua namespace của subject" **không làm workload cũ đổi verdict**. Vì thế phép biến đổi phải làm cho
*workload cũ* phụ thuộc vào đúng điều kiện này:

**Biến đổi:** trên một RoleBinding có subject `ServiceAccount S1:N`, đổi `subjects[i].namespace` từ `S1` sang một namespace **mới** `S2`, và thêm
`ServiceAccount S2:N` (để subject không treo lơ lửng). Workload chạy bằng `S1:N` giữ nguyên. Nếu danh tính gồm namespace, workload mất quyền
(nếu binding là đường duy nhất); nếu scanner ghép theo tên, nó vẫn coi workload có quyền.

* Relation: `fail_to_pass` trên control mức workload (Kubescape `C-0267`, `C-0272`), **chỉ** khi verdict nguồn là FAIL (có bằng chứng); nguồn PASS ⇒ `INCONCLUSIVE`, không phải vi phạm.
* Không ánh xạ control mức Role (`C-0015`, `C-0007`, `C-0035`, Trivy): Role vẫn được cấp cho `S2:N`, nên finding trên Role *đúng* là không đổi (quan hệ `fail_to_pass` sẽ sai).
  Trivy không có control cấp workload cho RBAC ⇒ **không ánh xạ** (NOT_OBSERVABLE).
* Precondition: binding→Role cục bộ, subject SA có namespace tường minh và có object, workload dùng SA đó, và **không đường nào khác** cấp quyền cho `S1:N`
  (không binding khác nêu SA, User `system:serviceaccount:S1:N`, hay Group `system:serviceaccounts`, `system:serviceaccounts:S1`, `system:authenticated`).
* Phản ví dụ: xem test `test_mr08_*` (đường khác cấp quyền; subject không namespace; Group; SA không có; SA mới thiếu; sửa thêm `roleRef`).
* Proof obligation: (i) danh tính SA gồm namespace; (ii) quyền chỉ cộng dồn, binding duy nhất là đường cấp ⇒ sau khi đổi namespace subject, `S1:N` không còn quyền; (iii) closed bundle.
  Giới hạn: lập luận (i) dựa trên suy diễn từ hai trích dẫn trên; chưa có review độc lập.

Pattern: KP3 (đổi một trường theo một chiều) **mở rộng** với một thêm object đồng hành; validator tùy biến chứ không dùng `expect_single_change`.

## 3. Dự đoán (viết TRƯỚC khi chạy; thí nghiệm ở mục 4)

Hạ tầng: Kubescape v4.0.15 trên (a) artifacts đã pin, (b) bản sao `drop-subject-ns` (bỏ `subjects[j].namespace == sa.metadata.namespace` trong C-0267).
Seed: `rbac-secrets-reader` (Pod `lab-c/reader-pod` chạy bằng `lab-c:reader`, nguồn C-0267 = FAIL). Các seed khác không có nguồn FAIL ở C-0267.

| | Dự đoán |
|---|---|
| (a) pinned, `rbac-secrets-reader`, C-0267 | nguồn FAIL ⇒ follow-up **PASS** ⇒ quan hệ thỏa ⇒ MR `PASS` |
| (b) mutant, `rbac-secrets-reader`, C-0267 | nguồn FAIL (không đổi so với pinned) ⇒ follow-up **FAIL** (mutant ghép theo tên) ⇒ **VIOLATION** |
| (a) và (b), các seed còn lại | nguồn PASS ở C-0267 ⇒ `INCONCLUSIVE` (baseline không đạt); **không** tính là phát hiện |
| Trivy | không ánh xạ ⇒ MR `SKIP mr_not_mapped_for_scanner` |

**Mutant được coi là *activated*** khi: verdict `C-0267` của workload ở follow-up **khác** giữa (a) và (b) trên cùng cặp.
**Bằng chứng MR phát hiện lỗi:** MR `VIOLATION` ở (b) mà `PASS` ở (a) trên cùng case (cùng `case_id`, cùng sha256 source/follow-up).
**Thí nghiệm inconclusive** nếu: nguồn C-0267 ở (a) khác (b) (đột biến đổi cả nguồn: khi đó không phân biệt được); hoặc (a) đã `VIOLATION`/`INCONCLUSIVE`
(thì scanner gốc vốn không thể hiện được quan hệ: MR không dùng để phân biệt); hoặc follow-up không hợp lệ.
**Mutant "equivalent"** (không thể bị kill bởi mọi input) không đúng với mutant này: có input kích hoạt (case ở trên), nên nếu (b) cũng `PASS` thì đó là bằng chứng *thiếu độ nhạy của MR hoặc dự đoán sai*, không phải mutant tương đương.

## 4. Kết quả

(điền sau khi chạy; xem phần dưới)

### Kết quả thực (2026-11-01; Kubescape v4.0.15; evidence: evidence lịch sử `mr08_mutation_2026-11-01` (không còn trong repository; xem `docs/poc/HISTORICAL_DATA.md`))

Hai lượt chạy cùng seed, cùng MR-08, cùng `case_id` và cùng sha256 của source và follow-up; chỉ khác artifacts (digest policy `8cfb2323…` đã pin so với `772c1faf…` của bản sao đột biến).

| Khóa so sánh | Pinned | Mutant (bỏ so sánh namespace của subject) | Dự đoán |
|---|---|---|---|
| `rbac-secrets-reader`, C-0267, `Pod/lab-c/reader-pod` | **FAIL → PASS, ok** | **FAIL → FAIL, violation** | đúng cả hai |
| cùng case, C-0272 | PASS → PASS, inconclusive (baseline không đạt) | giống | đúng |
| `rbac-workload`, `K1-role-namespace` (C-0267, C-0272) | PASS → PASS, inconclusive | giống | đúng |
| Trivy | `SKIP mr_not_mapped_for_scanner` ở mọi seed | n/a | đúng |

* **Mutant được kích hoạt:** verdict follow-up C-0267 khác nhau giữa hai scanner trên cùng cặp (PASS ↔ FAIL) và verdict nguồn giống nhau (FAIL ở cả hai).
* **MR-08 phân biệt được scanner gốc và mutant** trên đúng 1 case. Mutant này **sống sót** qua toàn bộ catalog 7 MR cũ (xem `MUTATION_GAP_ANALYSIS.md`).
* **Một chỗ dự đoán lệch về nhãn:** đã viết "MR `PASS`" cho scanner gốc, nhưng kết quả cấp case là **`PARTIAL`**, vì C-0272 trong cùng case `inconclusive` và checker không bao giờ báo PASS đầy đủ khi một phần phạm vi thiếu verdict. Khóa C-0267 đúng như dự đoán; chỉ nhãn cấp case khác. Điều này **không** làm yếu kết luận phát hiện (mutant: `VIOLATION`).
* `mr informative` cho MR-08: 2/12 so sánh mang thông tin (mỗi lượt chạy 1 khóa C-0267), 10 `INCONCLUSIVE`. MR-08 hiện chỉ phân biệt được trên **một seed** vì chỉ `rbac-secrets-reader` có nguồn C-0267 = FAIL.

### Giới hạn quan trọng (không được bỏ qua)

* **Vòng tròn thiết kế:** MR-08 được thiết kế *sau khi* biết mutant và ngay để giết mutant đó. Kết quả cho thấy MR **nhạy với lớp lỗi nó nhắm tới**, không phải tỉ lệ phát hiện lỗi nói chung và không phải phát hiện độc lập.
* **n = 1** case, **một** mutant, **một** control, **một** scanner.
* Scanner gốc cho `FAIL → PASS` cho thấy `C-0267` hiện xử lý namespace subject đúng ở mức quan sát này; **không** chứng minh MR-08 đúng, và property vẫn `author_reviewed`.
* Trivy chưa có control mức workload cho RBAC ⇒ MR-08 không kiểm Trivy.
