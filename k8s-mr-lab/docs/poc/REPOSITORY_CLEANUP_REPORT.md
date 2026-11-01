# Báo cáo dọn repository

Viết cho: người cần biết cái gì còn trong repository, cái gì đã bỏ và vì sao không mất khả năng kiểm toán.

## Còn lại (một khung, một bộ kết quả)

| Thành phần | Vị trí |
|---|---|
| MR catalog, requirements, properties | `mrs/` |
| Control registry (sinh) và policy mapping | `config/` |
| Runner, Checker, pipeline, MR | `src/` |
| Test (kể cả ràng buộc kiến trúc) | `tests/` (+ `tests/golden/`) |
| Công cụ thực nghiệm, báo cáo, kiểm hash | `scripts/` |
| Bộ kết quả chính thức duy nhất | `docs/evidence/poc_final/` |
| Tài liệu | `docs/architecture`, `docs/poc`, `docs/case_studies`, tài liệu phương pháp/giao thức |
| Ablation K1/N2 (do `triage_probe.py` ghi) | `docs/evidence/{k1_kubescape,n2_trivy}_ablation.json` |

Không còn thư mục `archive/`, không còn cấu hình, mapping hay script chạy V1/V2 (`test_no_legacy_mapping_checker_or_input_model_remains`).

## Đã bỏ và nơi khôi phục

Xem `HISTORICAL_DATA.md`: toàn bộ dữ liệu bị bỏ được sao lưu ngoài repository (16 416 tệp, 314 MB, manifest sha256, đã đối chiếu lại 0 tệp lệch) và còn nguyên trong lịch sử Git. Không rewrite history.

## Dữ liệu cũ vẫn được dùng (đã chuyển theo provenance)

`poc_final/kd001-old-scope/` (có manifest, ghi rõ chưa được chạy lại bởi khung hiện tại) và `tests/golden/seed_coverage_project_seeds.json`. Các test từng đọc evidence cũ nay đọc `poc_final`.

## Các thay đổi kèm theo

* `scripts/demo.sh` ghi vào `runs/demo/` (từng `rm -rf runs/trivy runs/kubescape`).
* `docs/evidence/**` là `-text` (`.gitattributes`); `scripts/verify_evidence.py` kiểm hash trên byte thô.

## Giới hạn

* Backup nằm trên máy tác giả (`D:\Code\KLTN\_backup\`), chưa được sao chép lên nơi lưu trữ khác; mất máy là mất bản sao `runs/` ngoài Git (phần trong Git vẫn còn).
* Các tài liệu giai đoạn còn nêu số liệu lịch sử; số liệu chính thức luôn là `POC_RESULTS.md`.
* `poc_final` chỉ đóng gói các case cần cho kết luận (không phải mọi case PASS của MR-01); sinh lại đầy đủ bằng `scripts/reproduce_official.sh`.
