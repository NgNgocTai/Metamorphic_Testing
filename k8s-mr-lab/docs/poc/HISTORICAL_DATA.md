# Dữ liệu PoC cũ: đã đi đâu

Viết cho: người gặp một tham chiếu tới thí nghiệm cũ (PoC v1, lượt thống nhất đầu tiên, các evidence giai đoạn trước) và cần biết dữ liệu ở đâu. Nội dung dưới đây **không** là kết quả chính thức; kết quả chính thức duy nhất là `docs/evidence/poc_final/` (`POC_RESULTS.md`).

## Đã bỏ khỏi working tree

| Thư mục (cũ) | Nội dung |
|---|---|
| `docs/evidence/archive/` | 9 thư mục thí nghiệm trước: `fault_variants`, `informative`, `kd001`, `mr07_dev`, `mr08_mutation`, `mr09_requirement_derived`, `mr_patterns_verification`, `p0_reverification`, `poc_v2_superseded` (lượt thống nhất đầu tiên, trước khi sửa phạm vi), `seed_coverage` |
| `docs/archive/` | 4 báo cáo giai đoạn trước (`RESEARCH_BASELINE_AUDIT`, `MR_ARCHITECTURE_AUDIT`, `MR_REFACTOR_REPORT`, `NEXT_STAGE_RESEARCH_REPORT`) |
| `docs/baseline/` + `scripts/snapshot_mr_behavior.py` | fingerprint hành vi MR-01..05 của PoC v1 |
| `scripts/make_evidence_pack.py`, `scripts/migration_impact.py` | gói evidence V1 và bộ phân loại migration (cần các lượt chạy cũ làm đầu vào) |
| `runs/` (ngoài Git) | raw output PoC v1 (`trivy`, `kubescape`, `heldout_poc_v1`, zip evidence), lượt trung gian, bản chạy `final`/`heldout` (đã đóng gói vào `poc_final`) |

## Nơi khôi phục

1. **Git:** mọi thứ trong `docs/` và `scripts/` ở trên còn nguyên trong lịch sử. Khôi phục bằng `git checkout <commit>^ -- k8s-mr-lab/docs/evidence/archive`, với `<commit>` là commit xóa (`git log --diff-filter=D --oneline -- k8s-mr-lab/docs/evidence/archive`); commit đứng ngay trước đợt dọn là `20de215`.
2. **Bản sao lưu ngoài repository** (máy tác giả, không commit): `D:\Code\KLTN\_backup\k8s-mr-lab_legacy_2026-11-01\`, 16 416 tệp, 314 MB, có `MANIFEST.json` (sha256 `cd028fde1f9d7999245520c575931b55fd1d4d54d6ef7381cb33d7cf620c8418`) và `verify_backup.py` (đã chạy: 0 tệp lệch). Chứa cả `runs/` ngoài Git.

## Dữ liệu cũ mà kết luận chính thức còn dựa vào (đã chuyển vào repository)

* `docs/evidence/poc_final/kd001-old-scope/`: MR-02 trên Kubescape v4.0.11 và v4.0.12 với **phạm vi cũ** (aggregator trên Role đích), cho kết luận "phạm vi cũ không phân biệt được hai bản" (5 so với 5). Chỉ tham chiếu, chưa được chạy lại bằng khung hiện tại.
* `tests/golden/seed_coverage_project_seeds.json`: coverage seed dùng trong test.

Các tài liệu giai đoạn (`docs/*.md`) còn nhắc tên các thí nghiệm cũ; số liệu của chúng là lịch sử và có thể khác `POC_RESULTS.md`.
