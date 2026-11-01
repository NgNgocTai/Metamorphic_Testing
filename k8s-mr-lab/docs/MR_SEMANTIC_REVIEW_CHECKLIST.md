# Checklist review ngữ nghĩa của một MR (thủ công, bắt buộc trước khi tin MR)

`k8s-mr-lab mr validate` chỉ là cổng **cấu trúc**: schema, truy vết, và việc MR sinh ra cặp hợp lệ, xác định, không sửa source.
Nó **không** chứng minh MR đúng với Kubernetes hay với control của scanner. Phần đó là review của con người; ghi kết quả
vào mục `rationale` của property và vào PR/biên bản.

| # | Câu hỏi | Bằng chứng cần có | Đạt? |
|---|---|---|---|
| 1 | Property có trích dẫn nguyên văn từ tài liệu Kubernetes (hoặc đặc tả khác) không, `verified: true` sau khi đã đối chiếu? | URL + câu trích | |
| 2 | Phép biến đổi có đúng bảo toàn (invariance) hoặc đổi đúng một chiều (controlled change) theo trích dẫn đó không? | Lập luận ngắn, kể cả khi có biến thể (defaulting, wildcard, nhiều đường cấp quyền) | |
| 3 | Control được ánh xạ có thật sự cam kết kiểm property này, trên đúng kind, ở đúng phiên bản scanner đã pin? | Đọc metadata/mã control (Trivy `custom.id` + `selector.subtypes`; Kubescape `rules[].match`) | |
| 4 | Scope so sánh có loại trừ những gì hợp lệ được phép đổi (ví dụ finding về chính object vừa thêm)? | `scope`, `known_non_equivalences` | |
| 5 | Có counterexample cụ thể làm MR sai, và test chứng minh precondition/validator từ chối nó? | Test trong `tests/unit` | |
| 6 | Verdict nguồn có tường minh hay suy luận (`pass_inferred`)? Có ghi giới hạn đó chưa? | `limits` | |
| 7 | Đã chạy trên scanner thật với seed phát triển và kiểm `comparisons.csv` (không chỉ `results.csv`)? | Đường dẫn evidence + sha256 | |
| 8 | MR đã đóng băng trước khi chạy tập đánh giá độc lập, và dữ liệu phát triển tách khỏi dữ liệu đánh giá? | Ghi chú partition | |

Một MR chỉ rời trạng thái `candidate` khi cả 8 mục có bằng chứng **và** có ít nhất một lượt đánh giá không dùng để thiết kế nó.
