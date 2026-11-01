# KD-001: tái hiện lỗi Kubescape #2579 trước/sau bản sửa bằng quy trình MR

Mục đích: chứng minh quy trình end-to-end *bản lỗi so với bản sửa* trên một lỗi đã công bố. Đây là **ca phát triển/minh họa (DEV)**, không phải đánh giá độc lập:
lớp lỗi này (ghép Role theo tên bỏ qua namespace) đã dẫn dắt thiết kế MR-02.

## 1. Chuỗi bằng chứng (đã xác minh từ nguồn)

| Sự kiện | Nguồn | Giá trị |
|---|---|---|
| Lỗi | kubescape/kubescape#2579 | `AggregateResourcesBySubjects` (repo `opa-utils`) ghép binding–Role chỉ theo `roleRef.kind + name`; 17/19 rule dùng aggregator bị ảnh hưởng |
| Bản sửa | kubescape/opa-utils PR #177, merge commit `83ec3801f0e3456e6efee2596d5998a2fc70d4b8`, 2026-07-31 | RoleBinding→Role phải cùng namespace; **namespace không khai báo coi là "không xác định", không phải sai lệch** |
| Tag `opa-utils` chứa bản sửa | `git tag --contains` trên bản clone | `v0.0.302` trở đi; `v0.0.301` **không** chứa (`merge-base --is-ancestor`) |
| `opa-utils` mà từng bản Kubescape dùng | `go.mod` tại tag | v4.0.10 → v0.0.300 · **v4.0.11 → v0.0.301 (trước sửa)** · **v4.0.12 → v0.0.303 (sau sửa)** · v4.0.13/14/15 → v0.0.312 |
| Ngày phát hành | GitHub releases | v4.0.11: 2026-07-22 · v4.0.12: 2026-08-12 · v4.0.15: 2026-09-29 |

⇒ Cặp scanner tự nhiên: **v4.0.11 (lỗi) và v4.0.12 (đã sửa)**. Bản sửa là mã Go của aggregator (không phải rego), nên dùng **cùng một bộ artifacts** (rego, framework) cho cả hai binary để cô lập thay đổi.
Seed của mình khai báo namespace tường minh, nên nhánh "namespace không xác định" của bản sửa không che mất lỗi.

## 2. Dự đoán (viết trước khi chạy)

Binary tải từ trang phát hành; artifacts: cùng `~/.kubescape` (digest `8cfb2323…`) cho cả ba binary (v4.0.11, v4.0.12, v4.0.15); `--use-artifacts-from`.

**Điểm bất định chính:** MR-02 hiện so sánh các control aggregator (`C-0015`, `C-0007`, `C-0035`, `C-0053`) trên **Role đích** (`bound_role`). Lỗi thêm Role *decoy* vào cảnh báo (cùng RoleBinding và ServiceAccount),
và bộ chuẩn hóa gán verdict cho **mọi** object trong cảnh báo ⇒ decoy, binding, SA bị FAIL còn **Role đích có thể vẫn PASS**.

| Cấu hình so sánh | v4.0.12 / v4.0.15 (đã sửa) | v4.0.11 (lỗi) |
|---|---|---|
| (A) mapping hiện tại: aggregator trên `bound_role` | không violation ở aggregator (đã quan sát ở v4.0.15) | **dự đoán: KHÔNG phát hiện** (Role đích không nằm trong cảnh báo sai) ⇒ cần ghi `NOT_DETECTED_BY_CURRENT_SCOPE` |
| (B) mapping mở rộng, **cùng MR-02**: aggregator trên `subject_sa` và `rolebinding` (đối tượng thật sự mang quyền của SA đích) | không violation | **dự đoán: phát hiện** (PASS → FAIL trên binding/SA vì decoy bị ghép) |
| `C-0267`, `C-0272` | VIOLATION như PoC (K1 không đi qua aggregator) | VIOLATION như PoC (rego không đổi, cùng artifacts) |

Nếu (A) không phát hiện thì đó là **kết quả**: phạm vi so sánh của MR-02 hẹp hơn thuộc tính nó định kiểm. (B) là cải tiến phạm vi **được gợi ý bởi lỗi đã biết** ⇒ thuộc DEV, không tính là phát hiện độc lập.
Mapping mở rộng chỉ dùng cho lần chạy này (file riêng trong thư mục chạy), **không** sửa `config/policy-mapping.yaml`.
**Tiêu chí kết luận:** "phát hiện" = có VIOLATION ở bản lỗi mà không có ở bản sửa trên cùng `case_id` (cùng sha256 source/follow-up) và cùng artifacts.
**Inconclusive nếu:** binary cũ không nạp được artifacts; verdict nguồn khác nhau giữa các binary (khi đó phải xem lại); hoặc binary không đúng phiên bản.

## 3. Kết quả (Kubescape v4.0.11 / v4.0.12 / v4.0.15, cùng artifacts digest `8cfb2323…`, local-file; evidence: evidence lịch sử `kd001_2026-11-01` (không còn trong repository; xem `docs/poc/HISTORICAL_DATA.md`))

Binary v4.0.11 và v4.0.12 tải từ trang phát hành; **sha256 trùng với `checksums.sha256` chính thức** của từng bản (`OFFICIAL_CHECKSUMS.txt`). Chạy MR-02 trên 7 seed (4 áp dụng × 2 profile = 8 cặp).

| Cấu hình so sánh | v4.0.11 (trước sửa) | v4.0.12 (sau sửa) | v4.0.15 |
|---|---|---|---|
| (A) mapping hiện tại | 5 VIOLATION (chỉ `C-0267`/`C-0272`) | 5 VIOLATION (giống hệt) | 5 VIOLATION (giống hệt) |
| (B) mapping mở rộng (+aggregator trên `ServiceAccount`, `RoleBinding`) | **7 VIOLATION**, thêm 28 khóa vi phạm ở `C-0015`, `C-0007`, `C-0035` | 5 (giống (A)) | 5 (giống (A)) |

* **Dự đoán đúng cả ba hàng:** (A) *không* phát hiện KD-001; (B) phát hiện; `C-0267/C-0272` không đổi giữa các bản vì rego và artifacts như nhau.
* **Chi tiết (B), v4.0.11 so với v4.0.12:** 28/114 khóa khác nhau, **chỉ ở verdict follow-up** (PASS → FAIL ở bản lỗi, PASS → PASS ở bản sửa); verdict nguồn giống nhau; sha256 source/follow-up giống nhau ở mọi cặp; chỉ `ServiceAccount` và `RoleBinding`, ba control aggregator; 7 cặp bị ảnh hưởng. v4.0.12 ≡ v4.0.15 ở mọi khóa.
* **Ý nghĩa:** hai binary khác nhau ở chính các control aggregator (mã Go mà `opa-utils#177` sửa), và MR-02 **với phạm vi mở rộng** thấy sự khác biệt đó trên các cặp, đúng cơ chế issue mô tả (cảnh báo gắn binding và service account với Role của namespace khác). Quy cho #177 là suy luận từ `go.mod` + cơ chế, không phải bisect (xem Giới hạn).

### Phát hiện về chính MR-02 (quan trọng hơn bản thân việc tái hiện)

**MR-02 như đang ánh xạ KHÔNG phát hiện KD-001** (hàng A). Thuộc tính MR-02 nhắm tới là quyền hiệu lực của *ServiceAccount đích*, nhưng các control aggregator chỉ được so trên *Role đích*, nơi lỗi không biểu hiện (cảnh báo sai gắn **decoy Role**, binding và SA; Role đích vẫn PASS).
Phạm vi so sánh hẹp hơn thuộc tính, một khoảng cách mà `mr informative` không bắt được vì nó chỉ xét khả năng *quan sát*, không xét việc đã *so sánh đúng đối tượng*.
Phạm vi (B) được gợi ý **bởi lỗi đã biết**, nên là cải tiến thuộc DEV. (Quyết định đã chốt ở mục "Cập nhật sau khi thống nhất khung" bên dưới: (B) trở thành phạm vi chính thức duy nhất.)

### Cập nhật sau khi thống nhất khung: phạm vi (B) là phạm vi chính thức duy nhất

Quyết định đã được áp dụng: `config/policy-mapping.yaml` giờ chỉ có **một** phạm vi MR-02 (aggregator trên `subject_sa` và `rolebinding`; `C-0267/C-0272` trên workload; `C-0057` là đối chứng âm; Trivy khai báo `unsupported`). Không còn mapping A hay B riêng. Phạm vi này được kiểm bằng validator tĩnh (control phải quan sát được thay đổi của MR), không chỉ bằng việc nó bắt được KD-001.
Chạy lại bằng pipeline chính thức (`--experiment-type historical-defect`, cây mã sạch, binary v4.0.11 và v4.0.12 tải lại và khớp `checksums.sha256`; evidence: `docs/evidence/poc_final/kd001-v4.0.1{1,2}/`, bảng: `docs/poc/POC_RESULTS.md`):

| Bốn verdict trên 64 khóa aggregator (ServiceAccount, RoleBinding) | số khóa |
|---|---|
| bản lỗi: nguồn PASS, follow-up FAIL; bản sửa: nguồn PASS, follow-up PASS | 28 |
| cả hai bản: nguồn PASS, follow-up PASS | 16 |
| cả hai bản: nguồn FAIL, follow-up FAIL | 20 |

Số case VIOLATION của MR-02: v4.0.11 = 7, v4.0.12 = 5 (v4.0.15 = 5). Verdict nguồn giống nhau ở mọi khóa; 28 khóa khác nhau chỉ ở verdict follow-up, thuộc `C-0015` (12), `C-0007` (8), `C-0035` (8), trên `ServiceAccount` (14) và `RoleBinding` (14), 7 cặp. Phạm vi cũ (aggregator trên Role đích, evidence `v4.0.1{1,2}-A`) cho 5 so với 5, tức không phân biệt được hai bản. Kết luận về phạm vi và giới hạn ở trên không đổi: một lỗi, một họ nguyên nhân, **không** thuộc mẫu số độc lập, và việc quy cho PR #177 là suy luận từ `go.mod` + cơ chế, chưa phải bisect.

### Giới hạn

* Một lỗi, một họ nguyên nhân (aggregator), một MR. **Không** phải tỉ lệ phát hiện; KD-001 cùng lớp lỗi với K1 đã dẫn dắt MR-02 nên **không thuộc mẫu số độc lập**.
* Chưa biết bản nào giữa 4.0.11 và 4.0.12 là "thay đổi duy nhất": mình chỉ chứng minh hai binary khác nhau ở kết quả, và `go.mod` cho thấy `opa-utils` đổi v0.0.301 → v0.0.303 (nhưng có thể còn thay đổi khác giữa hai release). Việc quy cho #177 dựa vào `go.mod` + cơ chế khớp mô tả của issue, chưa phải bisect.
* Artifacts (rego) của v4.0.15 được dùng cho cả ba binary; các binary cũ có thể mong đợi artifacts khác, nhưng cả ba đều nạp và chạy được (không SCAN_ERROR).
