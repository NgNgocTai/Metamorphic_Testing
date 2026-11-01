# Báo cáo tác động của migration lên kết quả

Viết cho: người phản biện cần biết con số nào đổi sau khi thống nhất khung và vì sao. Số liệu cũ **không** được giữ làm baseline; chúng chỉ là bằng chứng lưu trữ (raw evidence và git `4ca941e`) để đối chiếu. Kết quả chính thức duy nhất: `POC_RESULTS.md`.

Cách phân loại: `scripts/migration_impact.py` so từng case của các lượt chạy cũ với lượt chạy mới (cùng `case_id` = MR + seed + digest tham số) và gán `UNCHANGED | EXPECTED_CHANGE | NEW_BEHAVIOR | BUG_FIX | UNEXPECTED_REGRESSION | UNRESOLVED`. Một thay đổi chỉ là `EXPECTED_CHANGE` khi suy ra được từ khác biệt **đã ghi** giữa mapping cũ (git `4ca941e`) và mới (một cặp control×target bị bỏ/thêm, hoặc `reports_on` của registry khác `kinds` cũ). Verdict khác cho cùng một khóa so sánh, hoặc khóa đổi mà không có lý do, là `UNEXPECTED_REGRESSION` / `UNRESOLVED` và làm lệnh thoát khác 0 (BLOCKED). Nguồn cũ: các lượt `runs/{trivy,kubescape}` (PoC v1) và các thư mục trong `docs/evidence/` cho MR-06..09.

## 1. Tổng hợp

| Scanner | UNCHANGED | EXPECTED_CHANGE | NEW_BEHAVIOR | BUG_FIX | UNEXPECTED_REGRESSION | UNRESOLVED | BLOCKED |
|---|---|---|---|---|---|---|---|
| Trivy 0.75.0 | 57 | 20 | 7 | 0 | 0 | 0 | không |
| Kubescape v4.0.15 | 59 | 17 | 0 | 0 | 0 | 0 | không |

Lượt chạy độc lập trên Kalm-Benchmark (65 file, cùng selection) so với lượt cũ lưu ở `runs/heldout_poc_v1/`:

| Scanner | UNCHANGED | EXPECTED_CHANGE | NEW_BEHAVIOR | UNEXPECTED_REGRESSION | UNRESOLVED | BLOCKED |
|---|---|---|---|---|---|---|
| Trivy 0.75.0 | 350 | 73 | 195 | 0 | 0 | không |
| Kubescape v4.0.15 | 317 | 39 | 259 | 0 | 0 | không |

(NEW_BEHAVIOR của lượt độc lập: MR-06..09 chưa có trong lượt cũ.) (đếm theo case; bảng từng case: `docs/evidence/poc_final/migration_trivy.md`, `migration_kubescape.md`.) **Không có verdict nào của cùng một khóa so sánh thay đổi** giữa hai khung, nên không có hồi quy do scanner hay do pipeline; mọi khác biệt là khác biệt về phạm vi so sánh.

## 2. Từng thay đổi và nguyên nhân

| # | Thay đổi | Scanner | Case ảnh hưởng | Loại | Vì sao |
|---|---|---|---|---|---|
| 1 | MR-02: 5 check Trivy (KSV-0113/0048/0049/0112/0050) trên `bound_role` bị bỏ; MR-02 khai báo `unsupported` | Trivy | 12 (8 case PASS không còn được sinh; 4 dòng `SKIP mr_not_mapped_for_scanner` thay thế, mỗi seed một dòng) | EXPECTED_CHANGE | Mỗi check Trivy chỉ nhìn document nó đánh giá; MR-02 chỉ thêm một Role không liên quan nên 8/8 case cũ PASS **theo cấu trúc** (0 thông tin). Validator cấu trúc chặn lại mapping này |
| 2 | MR-07: 5 check Trivy trên `bound_role` bị bỏ; `unsupported` | Trivy | 8 (4 case PASS không còn được sinh; 4 dòng `SKIP`) | EXPECTED_CHANGE | Không check Trivy nào đọc subject `ServiceAccount` của RoleBinding (MR-07 đổi đúng trường đó) |
| 3 | MR-02: control aggregator của Kubescape (C-0015/0007/0035/0053) so trên `subject_sa` + `rolebinding` thay cho `bound_role` | Kubescape | 8 (mỗi case: −4 khóa, +8 khóa) | EXPECTED_CHANGE | Phạm vi cũ không quan sát được KD-001 (xem `POC_RESULTS.md`). Kết quả MR-02 trên v4.0.15 **không đổi** (5 VIOLATION như trước, cùng control C-0267/C-0272); chỉ số so sánh tăng 4 → 8 mỗi case |
| 4 | MR-02: C-0057 chuyển thành `role: control` | Kubescape | 8 (trong dòng 3) | EXPECTED_CHANGE | Không đổi verdict; đối chứng âm có tier `CONTROL` riêng và vi phạm ở đó bị gắn `UNEXPECTED_VIOLATION` |
| 5 | MR-01 (`ALL_OF_KIND`): control aggregator nay báo cáo trên cả `ServiceAccount`, `RoleBinding`, `ClusterRoleBinding` (registry `reports_on`), mapping cũ ghi `kinds: [Role, ClusterRole]` | Kubescape | 8 | EXPECTED_CHANGE | Normalizer vốn gán verdict của bộ ba (SA, Role, RoleBinding) cho mọi thành viên; registry ghi đúng điều đó thay cho danh sách kind cũ. +4..6 khóa mỗi case, mọi khóa mới đều PASS→PASS, result không đổi |
| 5b | **Phạm vi control tổng hợp (`scope_rule`)**: ServiceAccount/Role không được bind nằm ngoài phạm vi của control tổng hợp | Kubescape | so với lượt cũ: held-out 29 case INCONCLUSIVE → SKIP (MR-01 ×24, MR-05 ×3, MR-03 ×2), repo seeds 1 case MR-01 INCONCLUSIVE → SKIP; so với lượt thống nhất đầu tiên: held-out MR-01 65 PARTIAL → PASS và 26 INCONCLUSIVE → SKIP, MR-09 6 INCONCLUSIVE → SKIP | EXPECTED_CHANGE | Lượt thống nhất đầu tiên cho MR-01 65 PARTIAL vì đưa ServiceAccount không được bind vào `ALL_OF_KIND` (cả hai phía `NOT_EVALUATED`). Quy tắc phạm vi sửa điều đó: 0 so sánh có kết luận bị mất, 0 verdict đổi (`POC_RESULTS.md`); các khóa bỏ đi đều có trong `scope.json` của case. Held-out Kubescape MR-01 nay giống lượt cũ (UNCHANGED 317) |
| 6 | MR-08: Trivy khai báo `unsupported` (trước đó chỉ vắng) | Trivy | 7 | NEW_BEHAVIOR | Lượt cũ không chạy MR-08 trên Trivy; nay có 7 dòng `SKIP` kèm lý do |

Phần còn lại của UNCHANGED (Trivy 57, Kubescape 60) gồm toàn bộ MR-03, MR-04, MR-05, MR-06, MR-09 và phần lớn MR-01/07/08: cùng case, cùng verdict nguồn và follow-up, cùng kết quả, từng khóa một.

## 3. Điều gì **không** thay đổi (và vì sao đáng nói)

* Các kết quả đáng chú ý của PoC cũ vẫn nguyên: Trivy MR-05 (N2) 1 VIOLATION; Kubescape MR-02 (K1) 5 VIOLATION trên C-0267/C-0272; MR-07 `C-0267` FAIL→PASS 1 VIOLATION (UNRESOLVED về phân loại); MR-08 PARTIAL/INCONCLUSIVE.
* Không có BUG_FIX nào được tuyên bố: không thay đổi nào trong lần thống nhất sửa một lỗi kết quả. Điều được sửa là **phạm vi** (MR-02) và **tính truy vết** của cấu hình.

## 4. Giới hạn của phân tích này

* Chỉ so được những gì lượt cũ có: MR-06..09 cũ có evidence rời (`mr07_dev`, `mr08_mutation`, `mr09_requirement_derived`, `informative`). Lượt held-out cũ được giữ nguyên ở `runs/heldout_poc_v1/` (không bị ghi đè).
* Phân loại `EXPECTED_CHANGE` là máy suy ra từ khác biệt mapping/registry đã khai; người đọc vẫn nên xem lý do từng case trong bảng chi tiết.
