# RQ2 Effectiveness: giao thức đo

**RQ2:** framework có phát hiện được bất nhất / lỗi scanner không, và bằng chứng đến mức nào?
Ba nhóm sau **không bao giờ được cộng vào một con số "số bug"**:

| Nhóm | Định nghĩa | Đơn vị đếm | Trạng thái hiện tại |
|---|---|---|---|
| H. Lỗi lịch sử đã biết | lỗi đã công bố chính thức, có bản lỗi/sửa, reproducer, chưa dùng để thiết kế MR | lỗi đã adjudicate (họ nguyên nhân) | **0 mục đủ điều kiện** (`KNOWN_DEFECT_CATALOG.md`) |
| I. Lỗi chèn (mutant) | sửa mã/policy của **bản sao cô lập** | mutant (sau khi loại tương đương) | 2 thí nghiệm có dự đoán trước; **chưa có tập mutant** nên chưa có mutation score |
| N. Vi phạm mới quan sát | VIOLATION trên scanner nguyên bản | họ ứng viên đã tái hiện | K1, N2, MR-07 (`UNRESOLVED`); **0 confirmed** |

## 1. Chỉ số theo nhóm

**N (newly observed).** Báo đủ chuỗi, không nhảy bậc:
`raw violation dòng` → `cặp input duy nhất` (khử trùng theo sha256 source+follow-up) → `họ ứng viên` (`family_signature`) → `đã tái hiện` (`triage`) → `đã adjudicate` → `confirmed`.
Số hiện tại (PoC + candidate, Kubescape v4.0.15 / Trivy 0.75.0): 6 dòng Kubescape MR-02/MR-07 + 1 dòng Trivy MR-05 → 4 cặp duy nhất MR-02/05 (PoC) + 1 MR-07 → 3 họ → 3 `CANDIDATE_REPRODUCED` → **0 confirmed**.
Trạng thái dùng: `UNINVESTIGATED, REPRODUCED, FRAMEWORK_ISSUE, POLICY_OR_SCOPE_ISSUE, SCANNER_DEFECT_CANDIDATE, CONFIRMED_SCANNER_DEFECT, UNRESOLVED`; chỉ người nghiên cứu được đặt `CONFIRMED_*`.
**Báo động giả do MR/framework** = số VIOLATION được adjudicate là `FRAMEWORK_ISSUE` hoặc MR sai ngữ nghĩa, trên **mẫu số là số VIOLATION đã adjudicate đầy đủ**. Hiện: chưa adjudicate xong nên **không báo tỉ lệ**.

**H (known defects).** `detection = detected eligible distinct defects / all eligible distinct defects`, mẫu số chốt trước theo `scanner+version+mode+policy+property/control`
(không theo việc MR hiện có kích hoạt được lỗi; lỗi thuộc phạm vi mà không được kích hoạt vẫn ở mẫu số). Báo `k/n`; `n` nhỏ thì báo từng ca. **Hiện n = 0 ⇒ không có con số.**

**I (injected).** `mutation score = killed / (activated ∧ non-equivalent)`, với:
* *activated*: verdict của scanner đột biến khác scanner gốc trên ít nhất một khóa của cặp;
* *killed*: bộ MR báo kết quả khác (VIOLATION) ở scanner đột biến mà scanner gốc không báo, trên **cùng** `case_id` với sha256 source/follow-up bằng nhau;
* *equivalent*: không input hợp lệ nào làm hành vi khác; phải lập luận, không mặc định;
* *survived-not-activated* (không có input kích hoạt) **tách riêng**, vì nó nói về seed, không về MR.
Một thí nghiệm hợp lệ phải: (i) ghi dự đoán trước, (ii) toán tử đột biến chọn trước (bỏ một phép so sánh, đảo `==`/`!=`, bỏ điều kiện kind, bỏ điều kiện namespace...), (iii) MR/seed đóng băng trước khi chạy, (iv) mutant tự động hoặc theo toán tử nêu rõ, (v) không thiết kế MR *sau* mutant rồi tính vào mutation score.
**Hiện có:** `namespace-fix` (fix-validation, không phải mutant) và `drop-subject-ns` (1 mutant): bị MR-08 giết **nhưng MR-08 được viết sau và nhắm đúng mutant ấy**, nên đây là bằng chứng *độ nhạy của MR với lớp lỗi*, không phải điểm đột biến.

## 2. Baseline (cùng ngân sách) và điều không so được

| Baseline | Dùng để | Không dùng để |
|---|---|---|
| Source-only (quét C₁) | đo nền: số control×resource có verdict, độ ổn định | so khả năng phát hiện bất nhất |
| Quét lặp cùng input | nhiễu / không xác định của scanner (nền cho VIOLATION giả) | |
| Biến đổi ngẫu nhiên **hợp lệ** (thêm object không bind, đổi tên hợp lệ...) cùng số lần quét | so số VIOLATION trên lượt quét | tuyên bố "MR tốt hơn" khi chưa có ground truth để chấm violation nào đúng |
| Tập fixture có kết quả kỳ vọng (benchmark KALM) | so verdict với nhãn kỳ vọng | MR (oracle quan hệ) và fixture (oracle tuyệt đối) trả lời **câu hỏi khác nhau** |

Phải phân biệt *khả năng sinh test* (có bao nhiêu cặp hợp lệ, `informative`) với *khả năng chấm đúng/sai* (cần ground truth). Chưa có số liệu để nói phương pháp nào hơn.

## 3. Mỗi lần báo cáo RQ2 phải có

1. Bảng ba nhóm riêng biệt kèm mẫu số.
2. Tỉ lệ so sánh **mang thông tin** (`mr informative`), để PASS không bị đọc như bằng chứng.
3. Môi trường: version, mode, policy digest, mapping digest, MR/catalog commit, partition dữ liệu.
4. Danh sách VIOLATION chưa adjudicate, **không** gộp vào "lỗi tìm thấy".

## 4. Điều có thể nói hôm nay (và không thể)

Có thể: catalog tái tạo được baseline PoC (256/256, 386/386); 3 họ hiện tượng cần adjudication; 1 mutant bị một MR nhắm đúng nó giết; ~59% (Trivy) và ~98% (Kubescape, cận trên) so sánh là có thể quan sát.
Không thể: tỉ lệ phát hiện lỗi, mutation score, specificity/precision, "MR hiệu quả hơn phương pháp X", hay bất kỳ con số "đã tìm thấy N lỗi".
