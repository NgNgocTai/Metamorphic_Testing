# Audit: những gì chưa thống nhất trước migration, và đã xử lý thế nào

Nguyên tắc: audit trước, chỉ sửa chỗ chưa thống nhất, **không viết lại thành phần đã đúng**. Trạng thái "trước" là commit `4ca941e` cộng các thay đổi chưa commit của giai đoạn trước (đọc từ mã, không từ trí nhớ). Raw evidence và lịch sử git được giữ nguyên để kiểm toán.

## 1. Những điểm đã được thống nhất lại

| # | Trước migration | Vấn đề | Sau migration |
|---|---|---|---|
| 1 | `policy-mapping.yaml` có mục `controls:` (title, kinds, rego) **và** `control-inputs.yaml` (scope, kinds) sinh bởi `derive_control_inputs.py` | Hai mô tả "control đọc / báo cáo trên kind nào", cùng tên `kinds` nhưng nghĩa khác nhau (báo cáo trên vs đọc) | Một `config/control-registry.yaml` sinh từ policy đã pin (có `reads` và `reports_on` riêng, sha256 file nguồn, digest policy). Mapping không còn mô tả control. Đã xóa `control-inputs.yaml` và `derive_control_inputs.py` |
| 2 | Entry mapping `{control, target}` không có lý do; MR không hỗ trợ một scanner chỉ là danh sách rỗng hoặc vắng | Khoảng trống im lặng: không phân biệt "chưa làm" với "không thể" | Mỗi entry có `reason`; mọi (MR, scanner) không có entry phải nằm trong `unsupported` kèm lý do; `mr validate` từ chối khoảng trống |
| 3 | Phạm vi MR-02: control aggregator của Kubescape (C-0015/0007/0035/0053) so trên `bound_role`; 5 check Role của Trivy so trên `bound_role` | KD-001 cho thấy phạm vi này **không thể** phát hiện lỗi (verdict sai gắn ở ServiceAccount và RoleBinding, Role đích vẫn PASS); Trivy KSV-01xx chỉ nhìn document của chính nó nên bằng nhau theo cấu trúc | Một phạm vi chính thức: aggregator trên `subject_sa` + `rolebinding`; C-0267/0272 trên workload; Trivy khai báo `unsupported` với lý do. Đã kiểm tính quan sát được bằng validator (mục 3 của `UNIFIED_FRAMEWORK.md`), không đoán |
| 4 | C-0057 trong MR-02 là "control thí nghiệm" chỉ ghi trong test và tài liệu, mapping coi như control thường | Một so sánh không thể phản ứng lại được tính chung với các so sánh property | `role: control`; validator buộc nó **không** quan sát được thay đổi; tier `CONTROL` riêng, vi phạm = `UNEXPECTED_VIOLATION` |
| 5 | Tầng informative (`mr informative`) chỉ chạy offline trên evidence đã lưu, dùng mô hình đầu vào riêng | Kết quả chính thức của một lần chạy không nói được so sánh nào quan sát được thuộc tính | `informative.annotate` chạy trong `Runner.run_pair` cho mọi case; `assessment.json` và `comparisons.csv` có `role, tier, basis, engaged`. `mr informative` dùng cùng hàm trên evidence cũ |
| 6 | Liên kết MR ↔ yêu cầu ở `requirements.yaml` (`mr_ids`, `origin`, `status`); catalog không biết yêu cầu | Hai nơi có thể lệch; trạng thái yêu cầu gõ tay | Chỉ catalog nói (`requirements`, `origin`); `requirements.yaml` chỉ có `uncovered:`; trạng thái suy ra; `check_requirements` từ chối trường bị gõ tay |
| 7 | `triage.py` có `PROPERTY_PATTERN` với id MR-02/03/04/05 hardcode, và đọc `rego` từ mapping | Hành vi riêng của MR nằm trong core | `rule_probe` là thuộc tính của class MR; tên file nguồn lấy từ registry (`source`). Test chặn id MR/control hardcode trong core |
| 8 | Catalog không khai báo MR đụng object nào và trả target nào | Không kiểm được mapping với MR; target lạ chỉ lộ khi chạy | `touches`, `targets` bắt buộc; `static_keys` ném lỗi nếu `targets()` trả selector chưa khai báo; `exercise` kiểm trên mọi seed hợp lệ |
| 9 | `environment.lock.json` chỉ có digest mapping, version scanner, policy | Không truy được framework commit, schema, digest catalog/registry/seed, loại thí nghiệm | Khối `experiment` (`experiment.py`), đặt bởi chính lệnh `run` |
| 10 | Kiểm tra mapping chỉ thấy field `control`/`target` không rỗng và control có trong `controls:` | Không bắt control mồ côi, target lạ, vai trò sai, entry chết | `check_mapping` (bộ luật duy nhất cho mọi MR) |

## 2. Thành phần đã đúng, giữ nguyên

| Thành phần | Lý do giữ |
|---|---|
| `Runner.run_pair/run_seed` (thứ tự transform → validate_pair → quét → chuẩn hóa → check; cặp không hợp lệ không quét; hai môi trường khác nhau không so) | Đã là đường chạy duy nhất cho mọi MR; chỉ thêm `annotate` và provenance |
| `checker.RELATIONS`, `check`, `full_keys` | Oracle quan hệ chung cho mọi MR; chỉ thêm kiểm target đã khai báo trong `static_keys` |
| `normalize/trivy.py`, `normalize/kubescape.py`, `bundles.py`, `validation.py`, `scanners/` | Không chứa logic MR; không thay đổi |
| `transforms/` (cách biến đổi và tìm target) | Logic riêng của từng MR thuộc về đây; chỉ thêm `rule_probe` |
| Tooling seed, đóng gói và làm sạch evidence, `mr explain/trace/patterns/review-packet` | Đã dùng chung catalog; chỉ cập nhật chỗ đọc mapping |
| Lịch sử git, evidence thô (`runs/`, `docs/evidence/`) | Giữ để kiểm toán; không xóa, không viết lại |

## 3. Không còn tồn tại trong kiến trúc đang chạy

Mapping dạng cũ (`controls:` trong `policy-mapping.yaml`), `control-inputs.yaml`, `derive_control_inputs.py`, `PROPERTY_PATTERN`, trường `mr_ids/origin/status` của `requirements.yaml`, mapping "mở rộng B" dùng riêng cho KD-001. `tests/unit/test_unified_framework.py::test_no_legacy_mapping_checker_or_input_model_remains` chặn việc quay lại.

Tác động lên kết quả (phân loại từng case): `../poc/MIGRATION_IMPACT_REPORT.md`.
