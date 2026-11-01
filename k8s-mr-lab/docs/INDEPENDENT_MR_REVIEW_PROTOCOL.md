# Giao thức review độc lập một MR

Mọi property hiện tại ở `review_status: author_reviewed`. Tài liệu này định nghĩa cách một người **khác tác giả** kiểm tra một MR, và khi nào
trạng thái được phép đổi. **Không ai (kể cả công cụ) được tự đổi trạng thái này.** Khi chưa có reviewer, trạng thái hồ sơ là `PENDING_INDEPENDENT_REVIEW`.

## 1. Ai được là reviewer độc lập

* Không phải người viết MR/property, không phải người viết phép biến đổi/mapping.
* Có đủ kiến thức Kubernetes RBAC / Pod Security để tự đọc tài liệu; không cần biết mã dự án.
* Không được xem **trước** kết luận của tác giả về MR (chỉ xem phát biểu property, transformation và đầu vào): tránh neo.

## 2. Hồ sơ và quy trình

1. Tác giả sinh hồ sơ: `k8s-mr-lab mr review-packet MR-xx --out docs/review_packets/MR-xx.md`. Hồ sơ gồm: phát biểu property với trích dẫn, giả định, không tương đương
   đã biết, precondition, transformation, relation, scope, mapping control và input model, phản ví dụ và test, giới hạn, tham chiếu evidence, 8 câu hỏi, và một **mẫu quyết định để trống**.
2. Reviewer tự làm, theo thứ tự (không nhìn đáp án của tác giả):
   a. Đọc trích dẫn gốc trên trang tài liệu Kubernetes; xác nhận từng câu (Q1).
   b. Tự nghĩ **ít nhất hai** phản ví dụ cho phép biến đổi trước khi đọc danh sách của tác giả (Q2, Q3).
   c. Đọc rego/metadata của **mỗi** control được ánh xạ trong phiên bản đã pin (Q4); ghi control đọc những kind nào (`config/control-registry.yaml`).
   d. Chạy `mr informative` trên evidence và xác nhận control nào không quan sát được thay đổi (Q7).
   e. Chạy `mr validate` và `pytest tests/unit` (cổng cấu trúc: không phải bằng chứng ngữ nghĩa).
3. Reviewer điền mục 5 của hồ sơ và lưu bản đã điền cạnh bản sinh (`docs/review_packets/MR-xx.reviewed-<tên>.md`). Bản sinh tự động không bao giờ chứa quyết định.

## 3. Quyết định và hệ quả

| Quyết định | Điều kiện | Việc được phép |
|---|---|---|
| `ACCEPT` | trả lời đủ Q1–Q8, không phản đối còn lại, đã đọc rego đúng phiên bản | đổi `review_status` của **property** thành `independently_reviewed`, ghi tên/ngày vào `rationale` |
| `ACCEPT_WITH_CHANGES` | có chỉnh sửa precondition/scope/giới hạn | sửa, chạy lại review phần đã sửa; chưa đổi trạng thái |
| `REJECT` | phản ví dụ làm MR sai, hoặc control không cam kết property | giữ `candidate`/hạ MR, ghi lý do vào `limits` |

`independently_reviewed` **không** làm MR thành `mvp`. Rời `candidate` còn cần: `MR_SEMANTIC_REVIEW_CHECKLIST.md` đủ 8 mục, ít nhất một đánh giá không dùng để thiết kế MR, và quyết định của người hướng dẫn về việc đưa vào run mặc định.

## 4. Những gì reviewer KHÔNG xác nhận

Review độc lập xác nhận lập luận ngữ nghĩa và ánh xạ control. Nó không xác nhận: scanner có lỗi, kết quả chạy, tỉ lệ phát hiện, hay MR đúng với mọi phiên bản.

## 5. Trạng thái hiện tại

| MR | Property | Trạng thái | Hồ sơ |
|---|---|---|---|
| MR-02 | SP-RBAC-NS-ROLE-RESOLUTION | `PENDING_INDEPENDENT_REVIEW` | `docs/review_packets/MR-02.md` |
| MR-07 | SP-RBAC-SA-SUBJECT-IDENTITY | `PENDING_INDEPENDENT_REVIEW` | `docs/review_packets/MR-07.md` |
| MR-08 | SP-RBAC-SA-SUBJECT-NAMESPACE | `PENDING_INDEPENDENT_REVIEW` | `docs/review_packets/MR-08.md` |
| các MR khác | | `author_reviewed` | chưa có hồ sơ |

Chưa có reviewer độc lập nào. Giảng viên hoặc một bạn cùng lớp là ứng viên hợp lý; người đó cần ~1–2 giờ cho mỗi MR nếu đọc rego.
