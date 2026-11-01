# Từ MST-wi (Web) sang MR-first cho Kubernetes security scanners: bảng ánh xạ có căn cứ

Mỗi dòng ghi **nguồn của khẳng định**:
**[P]** = bài báo *Metamorphic Testing for Web System Security* (IEEE TSE 2023; đã đọc bản PDF trong thư mục dự án, mục và bảng được ghi kèm);
**[R]** = đã đọc trong repository `MetamorphicSecurityTesting/MST` hoặc `/CWE` (clone ngày 2026-11-01);
**[X]** = đề xuất / diễn giải của khóa luận này, **không** phải phát biểu của MST-wi.
Không có mục nào dựa vào trí nhớ về bài báo. Chưa đọc từng lớp của repo `SMRL_EclipsePlugin` (trình biên dịch SMRL → Java): không có kết luận nào về nó.

## 1. Khác biệt cốt lõi giữa hai bài toán

| | MST-wi | Đề tài này |
|---|---|---|
| SUT | hệ thống Web (Jenkins, Joomla) [P §10] | **scanner** Trivy / Kubescape, không phải Kubernetes [X] |
| Điều cần phát hiện | lỗ hổng bảo mật *của SUT* (CWE như vi phạm nguyên tắc thiết kế) [P §8] | **hành vi không nhất quán/sai của scanner** khi đánh giá cấu hình; CWE (nếu có) mô tả cấu hình sai mà control phát hiện, không phải nhãn cho lỗi scanner [X] |
| Input | chuỗi hành động Web của người dùng, thu bằng crawler + test script [P §6] | bundle YAML nhiều object (đồ thị tham chiếu) [X] |
| Oracle | quan hệ giữa output của input nguồn và follow-up (không có oracle tuyệt đối) [P §1, §8] | cũng là quan hệ giữa hai lần quét **cùng scanner, cùng phiên bản, cùng policy** [X] |
| Rủi ro oracle | MR có thể báo giả; tác giả đo specificity [P §10.2] | một VIOLATION chưa phải lỗi; cần triage và adjudication; cả hai lần quét có thể cùng sai [X] |

## 2. Quy trình tổng thể

| MST-wi | Kubernetes MR-first | Cách áp dụng | Giới hạn |
|---|---|---|---|
| 4 bước: chọn/đặc tả MR → biên dịch sang Java → thu thập dữ liệu → chạy framework [P §3, Fig.1] | chọn MR → sinh cặp → quét hai lần → chuẩn hóa → kiểm quan hệ [X] (`docs/CODE_WALKTHROUGH.md`) | cùng ý tưởng "đặc tả khai báo + thực thi tự động" | không có DSL/biên dịch: MR là Python + metadata YAML; lý do: chưa có biểu thức quan hệ nào vượt quá khả năng của cấu trúc hiện có [X] |
| Bước 1 thủ công, bước 2–4 tự động [P §3] | bước dẫn xuất MR thủ công; sinh/thi hành/so sánh tự động [X] | trung thực về chỗ nào cần con người | tự động hóa *dẫn xuất* MR từ OWASP/CWE chưa làm và không được tuyên bố |

## 3. Nguồn của MR

| MST-wi | K8s | Cách áp dụng | Giới hạn |
|---|---|---|---|
| Catalog 76 MR dẫn xuất từ **90 hoạt động kiểm thử OWASP** (16 được tự động hóa bởi 22 MR) và các loại lỗ hổng **CWE** về vi phạm nguyên tắc thiết kế (54 MR phát hiện 101 loại CWE); 15 MR vừa OWASP vừa CWE; tổng 102 loại lỗ hổng [P §8] | OWASP Kubernetes Top 10 **2025** chọn miền rủi ro; CWE phân loại điểm yếu cấu hình; tài liệu Kubernetes chứng minh ngữ nghĩa [X] | mỗi property trích dẫn nguyên văn từ tài liệu Kubernetes, mỗi tham chiếu có cờ `verified` (`mrs/security_properties.yaml`) | OWASP/CWE **không** chứng minh MR đúng. Số 76 MR của họ không phải chuẩn so sánh với số MR ở đây (miền và mẫu số khác) |
| Một hoạt động OWASP có thể cho nhiều MR; một số hoạt động không hưởng lợi từ MT [P §8] | một property có thể cho nhiều MR (ví dụ RBAC namespace → MR-02) và có property không có control quan sát được [X] | `status: candidate` + `NOT_OBSERVABLE` được ghi nhận như kết quả hợp lệ | |
| Ví dụ OWASP → MR: "thu link trang quản trị rồi truy cập trực tiếp bằng người dùng khác" → MR `CWE_266_..._OTG_AUTHZ_002` [P §8, Fig.2; R: `CWE_MRs/*.smrl`] | K1 (Role trùng tên) → MR-02 [X] | cùng thao tác tư duy: từ một mô tả kiểm thử suy ra "đổi cái gì, kỳ vọng quan hệ gì" | MR-02 được viết **sau khi biết** K1: dẫn dắt, không phải khám phá mù |

## 4. Template MR và pattern

| MST-wi | K8s | Cách áp dụng | Giới hạn |
|---|---|---|---|
| Mọi MR theo một template: vòng lặp trên action, `IMPLIES(precondition ∧ tạo follow-up ∧ chỉnh follow-up, điều kiện trên output)` [P Fig.9; R] | `applicable` ∧ `transform` ∧ `validate_pair` ⇒ quan hệ trên verdict [X] | tương ứng trực tiếp | khác biệt thiết yếu: ở MST-wi precondition sai thì "implication trivially holds" (không sinh follow-up) [P §8.1]; ở đây là `SKIP`/`INVALID_PAIR`/`INCONCLUSIVE`/`PARTIAL`, **không** bao giờ là PASS |
| Template **không định nghĩa trước**, rút ra từ >100 đặc tả [P §8.1] | các phần tử template (`P-*`, `G-*`, `S-*`, `O-*`) và nhóm KP1–KP3 rút ra từ 7 MR có sẵn [X] | đúng thứ tự: có MR cụ thể trước, phân loại sau | 7 MR là mẫu rất nhỏ; xem `MR_PATTERN_TAXONOMY_V2.md` |
| Phần tử: precondition (người dùng, action), sinh follow-up (cùng/khác người dùng; cùng/tập con/thêm/sửa action), điều kiện output (bằng, khác, predicate khác) [P Bảng 3] | tương đương K8s: precondition cấu trúc/tham chiếu/đóng; sinh follow-up viết lại/thêm/sửa/xóa; output equal/pass_to_fail/fail_to_pass [X] (`mrs/patterns.yaml: template_elements`) | trục "người dùng" của họ không có tương đương (scanner không có người dùng); trục "action" tương ứng "loại biến đổi" | tương ứng mang tính loại suy, không phải đồng nhất |
| Pattern = nhóm MR có **cùng tổ hợp phần tử**; một MR thuộc đúng một pattern; 23 pattern, 6 pattern có ≥5 MR, 12 pattern chỉ có 1 MR; P1 và P2 mỗi cái 13 MR [P §8.2, Bảng 4] | `k8s-mr-lab mr patterns` dựng ma trận MR×phần tử và nhóm các hàng giống hệt (cùng phương pháp) [X] | so được nhóm KP đặt tên tay với nhóm theo phần tử | KP1 và KP3 hiện *thô hơn* nhóm theo phần tử (xem ma trận); cần thêm MR mới trước khi kết luận |
| 72 MR (94%) có action precondition, 33 (43%) có user precondition [P §8.1] | tỉ lệ tương ứng chưa tính | chỉ tính khi có đủ MR | không so số liệu |

## 5. Dữ liệu đầu vào (source inputs)

| MST-wi | K8s | Cách áp dụng | Giới hạn |
|---|---|---|---|
| Crawljax duyệt giao diện, tạo đồ thị trạng thái; **source input = đường đi gốc→lá theo DFS**; nhận diện trạng thái bằng khoảng cách chỉnh sửa trang (ngưỡng 5%); chỉ cần URL + danh sách credential [P §6] | không có "giao diện để duyệt"; tương đương là **bộ sưu tập manifest/đồ thị object** từ benchmark và cấu hình thật [X] | `docs/EVALUATION_PROTOCOL_V2.md §2` đề xuất cách thu thập, đa dạng hóa, đo coverage seed | **chưa thực thi**: hiện chỉ có 8 seed (6 tổng hợp, 1 lịch sử, 1 invalid) |
| Bổ sung bằng **test script Selenium** để có chuỗi tương tác phức tạp mà crawler không đạt [P §6] | tương đương: seed viết tay theo property (như `rbac-secrets-reader`) và manifest benchmark [X] | giữ cả hai nguồn: tự động rộng, viết tay sâu | |
| Hàm `Input(i)`, `User(i)` truy vấn tập input [P §6] | `ConfigBundle.find/of_kind/index`, `k8s.py` helper [X] | "từ vựng miền" dùng chung | |

## 6. Thực thi, đánh giá

| MST-wi | K8s | Cách áp dụng | Giới hạn |
|---|---|---|---|
| Framework thực thi, kiểm quan hệ, lưu các lần không thỏa; thư viện `MR.java`, `Operations.java` (hàm miền như `isAdmin`, `cannotReachThroughGUI`), `OperationsProvider` tách SUT [R] | `Runner`, `checker`, `scanners/`, `normalize/`; `k8s.py` là từ vựng miền [X] | tách MR khỏi SUT: có | mã MST có trạng thái tĩnh toàn cục và đếm biểu thức bằng số dòng stack trace [R]: không bắt chước |
| Đánh giá RQ1–3: oracle problem, loại lỗ hổng phát hiện được, hướng dẫn testability [P §9] | RQ1 Applicability [X] | ánh xạ tương ứng | |
| RQ4 effectiveness: **sensitivity & specificity** trên Jenkins 2.121.1 và Joomla 3.8.7; 20 + 16 CVE, catalog chạm 8/20 và 5/16, tái hiện thủ công 8 + 2; tác giả báo 85% lỗ hổng phát hiện và specificity 99,81% [P §10, tóm tắt] | RQ2 Effectiveness [X] | **chỉ** báo sensitivity trên tập lỗi đã biết **đủ điều kiện**; specificity cần negative có nhãn | chưa có ground truth đủ lớn ⇒ không báo tỉ lệ (xem `KNOWN_DEFECT_EVALUATION_PLAN.md`) |
| RQ5 efficiency: thời gian chạy, tương quan với số input/follow-up [P §10] | RQ3 Efficiency & Practicality [X] | đo thời gian sinh, số lần quét, cache, chi phí triage | |
| Threats to validity: internal, conclusion, construct, external [P §11] | `docs/EVALUATION_PROTOCOL_V2.md §7` [X] | | |

## 7. Điều rút ra, và điều không được suy ra

* Học được: (1) template rút ra *sau* khi có nhiều MR; (2) pattern là phân loại theo tổ hợp phần tử; (3) precondition có hai mục đích: chọn nơi MR có nghĩa và tránh báo giả; (4) thu thập source input có hệ thống thay vì viết tay; (5) báo cáo sensitivity/specificity có mẫu số.
* Không suy ra: rằng framework này "theo MST-wi"; rằng số pattern/MR của họ là chuẩn; rằng một MR đúng chỉ vì nó thuộc một pattern.
