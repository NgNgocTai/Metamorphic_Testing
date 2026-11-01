# Báo cáo dọn repository

Viết cho: người cần biết cái gì còn dùng, cái gì chỉ để kiểm toán, và vì sao không có gì bị xóa mất bằng chứng.

## Phân loại

| Loại | Vị trí | Hành động | Lý do |
|---|---|---|---|
| ACTIVE | `mrs/`, `config/`, `src/`, `tests/`, `scripts/`, `seeds/` | giữ | một catalog, một registry sinh, một mapping, một pipeline |
| ACTIVE | `docs/evidence/poc_final/` | giữ (mới) | **bộ kết quả chính thức duy nhất**, gắn commit nguồn, có `manifest.json` sha256 |
| ACTIVE | `docs/poc/`, `docs/architecture/`, `docs/case_studies/`, `REPLICATE.md`, `README.md` | giữ, cập nhật | tài liệu canonical; số liệu sinh từ `poc_final` |
| ACTIVE | `docs/evidence/{k1_kubescape,n2_trivy}_ablation.json` | giữ nguyên chỗ | do `scripts/triage_probe.py` ghi và `DEFECT_TRIAGE_RESULTS.md` dẫn tới |
| ARCHIVE | `docs/evidence/archive/*` (9 thư mục thí nghiệm trước, kể cả `poc_v2_superseded_2026-11-01` = lượt thống nhất đầu tiên trước khi sửa phạm vi) | **di chuyển nguyên thư mục** (`git mv`), không sửa file | giá trị kiểm toán; manifest dùng đường dẫn tương đối nên vẫn đúng |
| ARCHIVE | `docs/archive/*` (4 báo cáo giai đoạn trước) | di chuyển | trùng vai trò với `poc/` và `architecture/`; số liệu cũ |
| ARCHIVE (ngoài Git) | `runs/trivy`, `runs/kubescape`, `runs/heldout_poc_v1`, `runs/heldout_poc_v2_superseded`, `runs/poc_v2_superseded`, `runs/evidence-pack-poc-v1.0.0.zip`, `runs/summary` | **không đụng** | raw output PoC v1 và lượt trung gian; `runs/` bị `.gitignore`, đây là bản duy nhất của một số raw output |
| REGENERABLE | `runs/final`, `runs/heldout` | giữ cục bộ | sinh lại bằng `docs/evidence/poc_final/run_official_experiments.sh`; bản đóng gói nằm trong `poc_final` |
| TEMPORARY | `__pycache__`, `.pytest_cache`, script/config tạm trong `runs/` (`_*.sh`, `_cfg*.yaml`) | dọn | sinh lại được; bản cần thiết đã nằm trong `poc_final` |

## Đã làm

* `docs/evidence/**` được commit là `-text` (`.gitattributes`); 115 file có blob LF nhưng manifest băm CRLF đã được lưu lại đúng byte gốc. `scripts/verify_evidence.py` kiểm hash trên byte thô và không bao giờ sửa file; có test.
* Sửa tham chiếu: `docs/evidence/<tên>` → `docs/evidence/archive/<tên>` trong tài liệu, script, test; `HOW_TO_ADD_AN_MR.md` → `architecture/HOW_TO_EXTEND_UNIFIED_FRAMEWORK.md`; `POC_REPORT_FOR_ADVISOR.md` → `poc/`.
* `scripts/demo.sh` không còn `rm -rf runs/trivy runs/kubescape runs/summary` (đã từng xóa raw output PoC v1): ghi vào `runs/demo/`.
* Không còn cấu hình hay mapping cũ chạy song song (kiểm bởi `test_no_legacy_mapping_checker_or_input_model_remains`).

## Không được xóa (và không xóa)

Raw evidence PoC v1, evidence KD-001, MR-09, MR-07/08, lịch sử Git (không rewrite), `runs/` nói chung, các file ngoài `k8s-mr-lab/` (`KLTN_*.md`, `KE_HOACH_*.md`, `*.pdf`, `project.zip` giữ nguyên).

## Giới hạn

* `docs/evidence/archive/poc_v2_superseded_2026-11-01` và các thư mục `docs/` cũ còn chứa số liệu của khung trước; chúng không tham gia báo cáo mặc định và không được trích làm kết quả chính.
* Các tài liệu giai đoạn (`docs/*.md` ngoài `poc/`, `architecture/`) vẫn nhắc số liệu lịch sử; nguồn số liệu chính thức luôn là `POC_RESULTS.md`.
* Chưa gộp thêm các tài liệu phương pháp (`MR_DERIVATION_METHODOLOGY`, `SECURITY_PROPERTY_DERIVATION_GUIDE`…) vì chúng không trùng nội dung.
