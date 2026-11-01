# Phân tích comparison "mang thông tin"

**Vấn đề.** Một MR `PASS` chỉ nói quan hệ được thỏa. Nếu control được so không thể đọc đối tượng mà MR đã đổi, quan hệ thỏa *theo cấu trúc*
và không nói gì về scanner. Không thể dùng số `PASS` như bằng chứng độ tin cậy của scanner nếu chưa tách phần này ra.

**Cách làm (chỉ lớp báo cáo).** `src/k8s_mr_lab/informative.py` + `k8s-mr-lab mr informative`. Không đổi checker, kết quả hay lịch sử PASS/VIOLATION.
Đọc evidence đã lưu (`diff.json`, `assessment.json`) và `config/control-registry.yaml` (sinh bởi `scripts/derive_control_registry.py` từ policy đã pin).

## 1. Khái niệm (tiêu chí khách quan, kiểm lại được)

| Khái niệm | Định nghĩa | Nguồn |
|---|---|---|
| executed | một `(control, resource)` có bản ghi so sánh | `assessment.json` |
| comparable | cả hai verdict là `PASS`/`FAIL` | `assessment.json` |
| observable (property-sensitive) | control **có thể đọc** ít nhất một object bị đổi | input model của control |
| informative | comparable ∧ observable ∧ không dựa trên PASS suy luận | trên |
| inconclusive | thiếu verdict, hoặc baseline của quan hệ có hướng không đạt | trên |

Input model: Trivy `judged_object` (check chỉ thấy tài liệu nó đang xét; đọc từ `selector.subtypes`), Kubescape `all_matched_kinds` (mọi kind trong `match` được nạp vào rego, có thể join).
**Observable là điều kiện cần, không đủ**: rego có thể không phụ thuộc trường đã đổi; vì vậy tỉ lệ "informative" của Kubescape là **cận trên**.

Các tầng (đầu tiên khớp): `INCONCLUSIVE` → `UNINFORMATIVE` (comparable nhưng control không quan sát được thay đổi; nếu lại là VIOLATION thì gắn cờ `UNEXPECTED_VIOLATION`) →
`WEAK` (comparable, observable, nhưng một PASS là suy luận) → `INFORMATIVE`. Cột `engaged` đánh dấu comparison có FAIL gắn resource ở một phía: check phản ứng
với resource đó (ví dụ Trivy `PASS suy luận → FAIL`).

## 2. Kết quả (lượt chạy ngày 2026-11-01, tất cả seed dự án, MR-01..07)

Nguồn: `docs/evidence/archive/informative_2026-11-01/{informative_comparisons.csv,informative_summary.json}`; run: Trivy 0.75.0, Kubescape v4.0.15.
Lượt chạy này tái tạo baseline PoC: 256/256 (Trivy) và 386/386 (Kubescape) so sánh của MR-01..05 **giống hệt**; lượt này có thêm so sánh do seed candidate và MR-06/07.

| scanner/MR | informative | weak | uninformative | inconclusive | tổng | tỉ lệ informative |
|---|---:|---:|---:|---:|---:|---:|
| trivy/MR-01 | 182 | 55 | 0 | 0 | 237 | 0,768 |
| trivy/MR-02 | **0** | 0 | **40** | 0 | 40 | **0,000** |
| trivy/MR-03 | 1 | 4 | 0 | 0 | 5 | 0,200 |
| trivy/MR-04 | 0 | 6 | 0 | 0 | 6 | 0,000 (6 `engaged`) |
| trivy/MR-05 | 1 | 0 | 0 | 0 | 1 | 1,000 |
| trivy/MR-06 | 0 | 1 | 0 | 0 | 1 | 0,000 (1 `engaged`) |
| trivy/MR-07 | **0** | 0 | **20** | 0 | 20 | **0,000** |
| **trivy tổng** | 184 | 66 | 60 | 0 | 310 | **0,594** |
| kubescape/MR-01 | 372 | 0 | 0 | 4 | 376 | 0,989 |
| kubescape/MR-02 | 44 | 0 | **6** | 0 | 50 | 0,880 |
| kubescape/MR-03 | 5 | 0 | 0 | 0 | 5 | 1,000 |
| kubescape/MR-04 | 6 | 0 | 0 | 0 | 6 | 1,000 |
| kubescape/MR-05 | 2 | 0 | 0 | 0 | 2 | 1,000 |
| kubescape/MR-06 | 1 | 0 | 0 | 0 | 1 | 1,000 |
| kubescape/MR-07 | 18 | 0 | 0 | 0 | 18 | 1,000 |
| **kubescape tổng** | 448 | 0 | 6 | 4 | 458 | **0,978** |

`unexpected_violations`: **không có**. Tỉ lệ tổng bị MR-01 chi phối (nhiều control × object); đọc theo từng MR.

## 3. Điều số liệu cho thấy

1. **MR-02 trên Trivy: 0/40 mang thông tin.** Check của Trivy xét từng tài liệu; thêm một Role ở namespace khác không đổi tài liệu nào mà check đọc. 40 so sánh PASS này đúng theo cấu trúc,
   **không** chứng minh Trivy giải quyết `roleRef` đúng namespace. (Trivy vẫn có thể lộ lỗi qua cơ chế gắn FAIL vào resource theo dòng và PASS suy luận cấp tệp; không được đo ở đây.)
2. **MR-07 trên Trivy: 0/20** (RoleBinding bị sửa, check đọc Role) ⇒ đã bỏ ánh xạ Trivy của MR-07.
3. **Kubescape MR-02: 6 so sánh UNINFORMATIVE** là control `C-0057` (privileged container), chỉ đọc workload; nó đóng vai trò **đối chứng** (kỳ vọng không đổi) chứ không thử property.
4. **Trivy MR-04/MR-06:** `PASS suy luận → FAIL` (7 so sánh `engaged`) cho thấy check phản ứng với thay đổi, nhưng phía PASS là suy luận nên không xếp INFORMATIVE.
5. **Không** thay đổi PASS/VIOLATION nào: 6 VIOLATION Kubescape và 1 VIOLATION Trivy ở lượt này giống PoC (họ K1, N2) và đều ở tầng INFORMATIVE.

## 4. Metric đề xuất cho báo cáo

`informative_comparisons` = số so sánh ở tầng INFORMATIVE. Luôn báo kèm: tổng số so sánh, theo scanner × MR, số WEAK/UNINFORMATIVE/INCONCLUSIVE, và nhắc rằng với Kubescape đây là cận trên.
**Không** dùng `PASS / tổng` làm chỉ số độ tin cậy; dùng `INFORMATIVE PASS / INFORMATIVE`.

## 5. Giới hạn

* Input model Kubescape (kinds được nạp) là điều kiện cần; chưa có phân tích phụ thuộc trường đã đổi.
* Mô hình Trivy `judged_object` giả định mỗi tài liệu được xét độc lập, đúng với `selector` đã đọc; khác biệt cấp tệp (PASS suy luận) nằm ở nhóm WEAK.
* Chỉ áp dụng cho evidence có `cases/` (lượt chạy mới, hoặc gói đóng gói từ `package_run_evidence.py`); các run PoC cũ đã dọn `cases/` nên không phân tích được nếu không chạy lại.
* Tầng chỉ mô tả khả năng quan sát, không cho biết scanner đúng hay sai.
