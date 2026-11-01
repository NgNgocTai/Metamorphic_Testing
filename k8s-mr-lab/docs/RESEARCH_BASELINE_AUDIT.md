# Audit baseline nghiên cứu (2026-11-01)

Nguyên tắc: tài liệu là nguồn tham khảo; **mã, log, kết quả test và evidence là cơ sở xác minh**. Mỗi mục ghi lệnh/tệp đã kiểm.
Nhánh: `research/mr-patterns`; baseline: tag `poc-v1.0.0` = `b3ff11b` (đã kiểm `git cat-file`). Chưa có commit/merge/push nào trong phiên này.

## 1. Kiểm chứng lại các kết quả đã báo cáo

| Khẳng định trước đó | Cách kiểm | Kết quả |
|---|---|---|
| 125 passed / 3 skipped (Windows) | `pytest` Windows (trước thay đổi phiên này) | đã có 125/3; sau khi thêm test phiên này: xem §1.1 |
| 128 passed / 0 skipped (WSL, scanner thật) | `pytest` trong bản sao cô lập chỉ gồm tệp đã commit, Trivy 0.75.0 + Kubescape v4.0.15 | **xác nhận**: 128 passed, 0 skipped |
| Pin scanner khớp | `k8s-mr-lab versions` | Trivy 0.75.0 / policy `b591e919…`; Kubescape v4.0.15 / `8cfb2323…`: OK |
| Trivy 256/256, Kubescape 386/386 so sánh khớp PoC | chạy lại toàn bộ seed, `scripts/compare_runs.py` (cả `results.csv` và `comparisons.csv`) | **xác nhận**: 41/41 & 256/256; 41/41 & 386/386; 0 khác biệt |
| K1/N2 là candidate, không confirmed | `triage --minimize` chạy lại | **xác nhận**: status/family/known_issue giống hệt (Trivy 1/1, Kubescape 5/5); `CANDIDATE_REPRODUCED`; 0 confirmed |
| Ablation K1/N2 | `scripts/triage_probe.py` chạy trong bản sao | **xác nhận**: `k1_kubescape_ablation.json` và `n2_trivy_ablation.json` **giống hệt byte** bản đã commit |
| Snapshot hành vi MR-01..05 bằng nhau | `scripts/snapshot_mr_behavior.py` so với `docs/baseline/mr_behavior_poc_v1.json` (loại MR mới) | **xác nhận**: IDENTICAL, 7 seed, 28 follow-up |
| Gói evidence PoC | `zipfile.testzip`, kiểm 138 sha256 trong `MANIFEST.sha256.json` | **xác nhận**: 138/138 khớp, 0 thiếu |
| Mapping control MR-06 | đọc `host_network.rego` và `c-0041.json` đã pin | khớp (KSV-0009, C-0041) |

Evidence chạy lại: `docs/evidence/p0_reverification_2026-11-01/` (có `p0.log`).

### 1.1 Test (kết thúc phiên)

Xem số cuối ở `docs/MR_REFACTOR_REPORT.md §9` và báo cáo cuối. `pytest` đầy đủ gồm test cấu trúc (Windows: 3 integration bị skip vì thiếu binary; WSL: 0 skip).

## 2. Kiến trúc thực tế (đã đọc mã)

```
catalog.yaml ─▶ registry (read_specs, load_catalog, active_mrs) ◀─ @implements trong transforms/*.py
                    │
seed ─▶ bundles.ConfigBundle ─▶ Runner.run_seed ─▶ run_pair ─▶ Scanner.execute ─▶ normalize/{trivy,kubescape}
                                                      │                               │
                                       validate_pair (cấu trúc)             NormalizedReport
                                                      └──────────▶ checker.check (RELATIONS) ─▶ Assessment ─▶ report / triage
mr_tools: list | validate | trace | patterns | explain | scaffold   (đọc catalog/properties/patterns/evidence, không tính verdict)
```
Chi tiết hàm: `docs/CODE_WALKTHROUGH.md` (đã đối chiếu tên hàm).

## 3. Đã hoàn thành / chưa triển khai

| Đã hoàn thành (có bằng chứng) | Chưa triển khai |
|---|---|
| 5 MR PoC, adapters, normalizers, checker, triage, evidence | tự động dẫn xuất MR từ OWASP/CWE (không làm và không tuyên bố) |
| catalog một nguồn, `@implements`, 3 pattern + ma trận phần tử, property catalog có `verified` | review ngữ nghĩa **độc lập** (mọi property là `author_reviewed`) |
| MR-06, MR-07 `candidate` có DEV evidence | đánh giá độc lập / held-out cho MR mới; known-defect (0 mục đủ điều kiện) |
| công cụ fault-variant Kubescape + 2 thí nghiệm có dự đoán trước | fault-variant cho Trivy; tập mutant có toán tử chọn trước; mutation score |
| `mr explain/patterns` | thu thập seed có hệ thống > 8 seed; ghép linked bundle tự động |
| replication package: phần lớn thành phần có | `REPLICATE.md` chạy từ môi trường sạch, lockfile/container, làm sạch đường dẫn cục bộ |

## 4. Rủi ro và sai lệch còn tồn tại

1. **Báo cáo cũ thổi phồng một chút** (đã sửa ở phiên trước): "verdict giống hệt trên 41 dòng" chỉ so verdict ở dòng VIOLATION; nay so cả `comparisons.csv`. Rà soát tiếp các câu "giống hệt/đã xác nhận" trong `POC_REPORT_FOR_ADVISOR.md` chưa làm (ngoài phạm vi phiên này).
2. **Phụ thuộc người đọc**: `results.csv` để trống verdict ở dòng PASS; luôn đọc `comparisons.csv` (đã ghi vào hướng dẫn).
3. **PASS của Trivy là suy luận** (mọi so sánh Trivy "PASS→PASS" là "không có FAIL gắn vào resource").
4. **MR dẫn dắt**: MR-02, MR-05, MR-07 viết sau khi biết hành vi scanner; K1/N2 là chính chúng.
5. **Seed ít (8)**: mutant `drop-subject-ns` sống sót một phần do seed (`EVALUATION_PROTOCOL_V2 §5`).
6. **Raw evidence chứa đường dẫn cục bộ** (`/home/<user>/…`).
7. **Policy bundle Trivy tải một lần** (2026-10-28): cần nguồn lưu cố định cho tái lập từ máy sạch.
8. `mr validate` là cổng cấu trúc: không thay thế review ngữ nghĩa.

## 5. Thay đổi an toàn đã thực hiện / không nên thực hiện

* Đã: chỉ thêm (metadata `template`, property fields, MR-06/07 candidate, công cụ, tài liệu, evidence). Không sửa adapter, normalizer, checker logic, golden, hành vi MR-01..05. Mọi thay đổi được snapshot và so sánh.
* Không nên: nâng MR-06/MR-07 lên `mvp` (sẽ thêm hàng vào mọi run mặc định và làm lệch baseline); đổi pin scanner trong track baseline; sửa MR sau khi xem kết quả held-out; viết lại `runner.run_pair` (một nơi gọi, test bao phủ, rủi ro lệch artifact).
