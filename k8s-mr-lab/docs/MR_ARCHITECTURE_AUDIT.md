# Kiểm toán kiến trúc xây dựng MR (Phase 1)

Đối tượng: `k8s-mr-lab` tại tag `poc-v1.0.0` (commit `b3ff11b`). Mọi kết luận dưới đây dựa trên việc đọc code; mục
"Đề xuất" ghi rõ khi chưa có bằng chứng. Baseline trước khi sửa: **80 passed, 3 skipped** (integration cần binary
Trivy/Kubescape, máy kiểm toán không có).

## 1. Các giả thuyết ban đầu được kiểm tra

| # | Giả thuyết | Kết luận | Bằng chứng |
|---|---|---|---|
| H1 | Metadata MR khai báo ở cả catalog và class | **Xác nhận một phần** | `id, name, category, relation` có ở cả `catalog.yaml` và class của 5 MR; `registry.load_catalog` chỉ so `relation`, không so `name/category`. Trường `property` ở class (slug) **không được code nào đọc** (dead metadata) và khác dạng với `property` của catalog (câu văn) |
| H2 | Mỗi MR tự cài nhiều phương thức cấu trúc giống nhau | **Xác nhận một phần** | MR-03/04/05: `applicable` = "có candidate?", `generate_parameters` = "một case/candidate" (cùng khuôn). MR-04/05: `validate_pair` = "đúng 1 thay đổi tại path X từ a sang b". MR-03/05: block "SA bound → workload" giống hệt. **MR-01 và MR-02 không trùng với ai**: logic riêng thật sự |
| H3 | Chưa phân biệt requirement / property / pattern / executable MR | **Xác nhận** | catalog chỉ có `category` (R3/R4/R9) và `property` dạng văn xuôi; không có pattern, không có nguồn |
| H4 | Chưa có quy trình truy vết từ tiêu chuẩn | **Xác nhận** | Không có OWASP/CWE/PSS ở bất cứ file nào trước đây |
| H5 | `k8s.py` chưa thành hệ primitive | **Bác bỏ phần lớn** | `k8s.py` đã là tập helper thuần Kubernetes, không biết scanner, dùng lại ở 3 MR. Chỉ thiếu 1 helper (`workloads_of_service_accounts`) |
| H6 | Thêm MR mới phải sửa nhiều chỗ | **Xác nhận** | Thêm MR = file transform + `import` trong `registry.py` + `MR_CLASSES` + `catalog.yaml` + `policy-mapping.yaml` + test |
| H7 | Runner đan xen điều phối/kiểm thử/evidence | **Xác nhận một phần, không sửa** | Xem 3.3 |

## 2. Phát hiện ngoài giả thuyết

1. **Import vòng** `checker.py ↔ registry.py` (chỉ để type `MappingEntry`) sẽ xuất hiện ngay khi registry cần `RELATIONS`. Đã xử lý bằng `TYPE_CHECKING`.
2. **Lỗi có từ trước:** `PrivilegedFlip.validate_pair` so sánh `(op, old, new) != ("change", False, True)`. Trong Python `1 == True`, nên follow-up có `privileged: 1` được coi là hợp lệ. Bắt được nhờ test mới; validator dùng chung hiện so cả kiểu. Pair hợp lệ không đổi.
3. Catalog trùng `id` bị `dict` nuốt im lặng (bản sau đè bản trước). Nay là lỗi.

## 3. Từng module

| Module | Trách nhiệm | Phụ thuộc vào nó | Trùng lặp? | Cần refactor? |
|---|---|---|---|---|
| `bundles.py` | Nạp/ghi bundle, digest, span | mọi module | Không | Không |
| `k8s.py` | Helper miền K8s thuần | transforms | Có 1 block (SA→workload) | Thêm 1 helper |
| `validation.py` | Diff cấu trúc, validate nguồn | transforms, runner | Mẫu "đúng 1 thay đổi" nằm rải ở MR | Thêm `expect_single_change` |
| `model.py` | Kiểu dữ liệu, trạng thái | tất cả | Không | Không |
| `transforms/*` | 5 MR + `base.py` | registry, scripts | H1, H2 | **Có** (xem report) |
| `registry.py` | Nạp catalog + mapping, ràng class↔catalog | runner, cli | Import tay 5 class | **Có** |
| `checker.py` | Oracle quan hệ trên verdict đã chuẩn hóa | runner | `_compare` là chuỗi `if` | Biến thành bảng `RELATIONS` |
| `runner.py` | Điều phối scan + ghi evidence | cli, triage | Xem 3.3 | Không |
| `scanners/`, `normalize/` | Chạy và chuẩn hóa từng scanner | runner | Không | **Không**, độc lập với MR |
| `report.py`, `triage.py` | Tổng hợp, tái hiện | cli | Không | Không |

### 3.3 Vì sao không tách `EvidenceWriter` khỏi `runner.py`

`Runner.run_pair` (~85 dòng) làm tuần tự: transform → validate → ghi file → scan ×2 → ghi invocation → check → ghi
provenance. Nó dài, nhưng: (a) chỉ có **một** nơi gọi, (b) runner **không biết chi tiết MR nào**: chỉ gọi
`applicable / generate_parameters / transform / validate_pair / targets` và đọc `relation`, `all_failures` (đã kiểm bằng grep),
(c) test hiện có (`test_runner.py`) dùng fake scanner bao phủ cả luồng. Tách ra chỉ đổi cách chia file, không giải quyết
vấn đề đang gặp, và rủi ro làm lệch artifact của evidence pack đã băm. Ghi vào future work, không làm.

## 4. Nguyên tắc đã áp dụng

Chỉ trừu tượng hóa phần có **ít nhất 2 MR thật sự dùng chung**. KP1 (2 MR lúc audit; 3 từ khi có MR-07) và KP2 (1 MR) có pattern trong catalog
nhưng **không có base class**, vì validator của chúng khác nhau thật (bất biến khác nhau). Chỉ KP3 và "per-candidate"
có code chung.
