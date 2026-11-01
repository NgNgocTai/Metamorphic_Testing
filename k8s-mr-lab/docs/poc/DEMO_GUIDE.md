# Hướng dẫn demo PoC (khung thống nhất)

Viết cho: người trình bày PoC trước giảng viên. Mọi lệnh chạy từ thư mục `k8s-mr-lab/` trong Ubuntu (WSL) có Trivy 0.75.0 và Kubescape v4.0.15 đã pin; bước 1–3 không cần scanner. `PY=~/mrlab-venv/bin/python`.

## Thông điệp cần truyền tải (một phút)

1. Một MR vừa **sinh** follow-up vừa là **oracle quan hệ**; cùng scanner chạy trên hai phía, không có oracle độc lập.
2. Có **một** cách khai báo MR, **một** cơ chế ánh xạ control và scope, **một** pipeline, **một** bộ kết quả chính thức (`docs/poc/POC_RESULTS.md`, sinh từ evidence).
3. Kết quả trung thực: mỗi so sánh có `role`, `tier`, `basis`; "quan hệ thỏa" tách khỏi "verdict có quan sát được thuộc tính".

## Kịch bản

| # | Lệnh | Nói gì |
|---|---|---|
| 1 | `$PY -m k8s_mr_lab mr list` và `mr explain MR-02` | catalog duy nhất; MR-02 khai báo `origin`, `requirements`, `touches`, `targets`; mapping hiển thị lý do từng control |
| 2 | `$PY -m k8s_mr_lab mr validate` | cổng cấu trúc: schema, truy vết, **mapping/scope** (không mồ côi, không khoảng trống im lặng, vai trò đúng), chạy MR trên mọi seed hợp lệ |
| 3 | `$PY -m pytest tests/unit/test_unified_framework.py -q` | ràng buộc kiến trúc: không hardcode MR/control trong core, một đường chạy, thêm MR không sửa core |
| 4 | `scripts/demo_mr02.sh` (~15 s, Kubescape thật) | C1 → C2 (thêm Role trùng tên khác namespace) → cùng scanner hai lần → `C-0267` PASS→FAIL → `CANDIDATE_REPRODUCED`, **chưa phải bug đã xác nhận** |
| 5 | mở `docs/poc/POC_RESULTS.md` | bảng kết quả toàn bộ MR trên hai scanner, tầng informative, violation |
| 6 | mở mục KD-001 trong `POC_RESULTS.md` | lỗi lịch sử kubescape#2579: bản lỗi v4.0.11 vs bản sửa v4.0.12; MR-02 phạm vi chính thức phát hiện, phạm vi cũ không |
| 7 | mở mục MR-09 mutation | lỗi tiêm vào `C-0015` (bỏ verb `watch`) bị MR-09 phát hiện; MR-09 dẫn xuất từ yêu cầu R08 trước khi nhìn scanner |
| 8 | `docs/poc/MIGRATION_IMPACT_REPORT.md` | số liệu nào đổi sau thống nhất và vì sao (mọi case được phân loại) |

## Câu hỏi thường gặp

* **Có phát hiện lỗi mới không?** Không. Có 2 họ ứng viên (K1 Kubescape, N2 Trivy) và 1 lỗi lịch sử tái hiện (KD-001) cùng 1 lỗi tiêm; tất cả đều là lớp lỗi biết trước hoặc tiêm, không phải tỉ lệ phát hiện.
* **PASS nghĩa là gì?** Quan hệ MR thỏa. Với Trivy, PASS là suy luận (`basis = inferred_pass`, tier WEAK).
* **Vì sao MR-02 không có phạm vi Trivy?** Mọi check Trivy được ánh xạ chỉ nhìn đúng document nó đánh giá, nên không thể quan sát một Role không liên quan; khai báo `unsupported` với lý do thay vì so sánh những thứ không thể phản ứng.
* **Con số cũ đâu?** Giữ ở evidence và lịch sử git để kiểm toán; báo cáo tác động migration giải thích từng khác biệt.

## Bổ sung: phạm vi MR-01 (nếu được hỏi về PARTIAL trên Kalm)

Mở mục "Effect of the control-scope rule" trong `POC_RESULTS.md`: 1159 → 780 so sánh, 0 so sánh có kết luận bị mất, 0 verdict đổi. Nói rõ: lượt Kalm là external regression (chính nó làm lộ vấn đề), và quy tắc phạm vi suy ra từ đối tượng nguồn, không từ output scanner.
