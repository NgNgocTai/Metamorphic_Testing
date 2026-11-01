# Phân tích khoảng trống từ thí nghiệm đột biến

## 1. Đọc lại đúng thí nghiệm cũ (evidence lịch sử `fault_variants_2026-11-01` (không còn trong repository; xem `docs/poc/HISTORICAL_DATA.md`))

Đột biến: trong rego `C-0267` của bản sao artifacts, bỏ dòng `rolebinding.subjects[j].namespace == sa.metadata.namespace`
(`scripts/fault_variant_kubescape.py`; digest policy khác bản đã pin ⇒ track riêng). Bộ MR: MR-01..05 và MR-07.

Con số phải đọc đúng (đã tính lại từ `results.json` / `comparisons.csv`):

| Đại lượng | Giá trị | Ghi chú |
|---|---|---|
| Dòng kết quả | 47 | gồm 16 `SKIP` và 1 `INVALID_SOURCE` |
| Cặp **thực sự được quét** | **30** | MR-01: 11 · MR-02: 8 · MR-04: 5 · MR-07: 4 · MR-03: 1 · MR-05: 1 |
| Khóa so sánh (control×resource) | 404 | |
| Khóa nằm trên **control bị đột biến** (C-0267) | **21 / 404** | 4 resource: 3 workload nhưng chỉ `reader-pod` có nguồn FAIL |
| Khóa có verdict khác giữa scanner gốc và mutant | **0 / 404** | mutant **không được kích hoạt** ở bất kỳ khóa nào |

Cách nói "46/46 case" trước đây **dễ gây hiểu nhầm**: 46 là số dòng kết quả có mặt ở cả hai lượt (gồm SKIP), không phải số cặp được quét (30).
Kết luận đúng: mutant không bị phát hiện vì **không có đầu vào nào làm nó biểu hiện**.

## 2. Vì sao mutant sống sót (phân loại)

| Giả thuyết | Đúng? | Bằng chứng |
|---|---|---|
| Mutant tương đương (không thể thấy bằng mọi input) | **Không** | có input làm nó khác: MR-08 + `rbac-secrets-reader` (mục 4) |
| Mutant không được kích hoạt bởi input hiện có | **Có (chính)** | 0/404 khóa khác; mọi binding trong seed có `subject.namespace` = namespace của SA |
| Thiếu seed | **Có** | `link:cross_namespace_subject` = 0 và `multi_namespace` = 0 (`SEED_COVERAGE_REPORT.md`) |
| Thiếu độ nhạy của MR | **Có, nhưng phụ thuộc seed** | không MR cũ nào làm *workload bị ràng buộc* phụ thuộc vào namespace của subject; MR-02 thêm Role, MR-07 đổi dạng subject mà giữ namespace |
| Thiếu kiểm thử tổng quát (control không được ánh xạ) | một phần | `C-0267` được ánh xạ cho MR-02/03/05/07; không đổi gì |

Hệ quả: đây là khoảng trống của **cả catalog lẫn seed**; chỉ thêm seed (hai SA cùng tên khác namespace) cho MR cũ vẫn không đủ, vì MR-02 thêm Role chứ không đổi cách binding nhắm tới SA.

## 3. Ứng viên MR để lấp khoảng trống

MR-08 `sa-subject-namespace-shift`: xem `SUBJECT_NAMESPACE_MR_CANDIDATE.md` (property, biến đổi, relation, scope, phản ví dụ, proof obligation, dự đoán viết trước).

## 4. Kết quả có đối chứng

Trên cùng đầu vào, MR-08 báo `fail_to_pass` thỏa ở scanner gốc (`C-0267` FAIL → PASS) và **VIOLATION** ở mutant (FAIL → FAIL). Mutant được kích hoạt và bị MR-08 phát hiện trên 1 case.

## 5. Giới hạn và cách đọc

* MR-08 được viết *sau* khi biết mutant: kết quả nói về **độ nhạy của MR đối với lớp lỗi nhắm tới**, không phải tỉ lệ phát hiện.
* Một mutant, một control, một case. **Không báo mutation score.** Muốn có số có nghĩa cần tập mutant chọn trước (bỏ một phép so sánh, đảo `==`/`!=`, bỏ một điều kiện kind...) trên cả Trivy và Kubescape, loại mutant tương đương, và MR/seed đóng băng trước khi xem kết quả.
* Mutant tạo ra bằng sửa tay một dòng rego, không phải bộ toán tử tự động.
* Đây là hiểu biết về catalog + seed của chính dự án, không phải về chất lượng Kubescape.
