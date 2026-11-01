# Sinh source input có hệ thống (V2)

MST-wi: Crawljax duyệt giao diện thành đồ thị trạng thái; source input là đường đi gốc→lá theo DFS; bổ sung bằng test script Selenium cho chuỗi phức tạp
(bài báo §6). Kubernetes không có "giao diện để duyệt", nên tương đương là **thu thập cấu hình** rồi **chọn và dựng bundle có ngữ nghĩa**.
Phân biệt **đã làm** và **đề xuất**.

## 1. Nguồn seed

| Nguồn | Đã làm? | Provenance cần ghi | Rủi ro |
|---|---|---|---|
| Seed dự án (tổng hợp, lịch sử) | **có** (6 duy nhất) | file trong repo | viết tay, thiên về MR đã có |
| KALM Benchmark | **đã khảo sát** (238 manifest) | commit, license, sha256 từng tệp | đã dùng ở PoC ⇒ không còn "mù"; mỗi tệp một lỗi đơn lẻ |
| ISSTA benchmark (có trên máy) | chưa | nguồn, phiên bản | chưa đọc cấu trúc, chưa kiểm license |
| Cấu hình công khai (Helm chart đã render, kustomize) | chưa | repo, commit, giấy phép | giấy phép; chọn mẫu thiên lệch |
| Bundle ghép từ nhiều manifest (linked bundle) | chưa | liệt kê tệp thành phần + lý do ghép | ghép sai ngữ nghĩa (đúng lỗi mà đề tài tìm) |

Quy tắc: không dùng lại tập đã quan sát kết quả để tuyên bố phát hiện mù; mọi nguồn ngoài ghi *tiêu chí chọn mẫu trước khi chạy scanner*.

## 2. Công cụ đã có (`k8s-mr-lab seeds ...`, tất định, không scanner)

* `inventory`: mỗi seed → hợp lệ?, digest nội dung, token đặc trưng, trùng nội dung, phân vùng.
* `coverage [--with-mr]`: phủ theo chiều trên 52 token định nghĩa trước; số seed mà mỗi MR áp dụng được.
* `select --k N`: **phủ tập token tham lam**, hòa thì chọn theo `(root, seed_id)`; không dùng ngẫu nhiên nên lặp lại được.
* `split --evaluation-percent P`: chia `development`/`evaluation` bằng `sha256(salt + digest nội dung) % 100`; seed thuộc phân vùng `DEV`/`REGRESSION` luôn là `development`
  (chúng đã định hình MR). Cùng nội dung ⇒ cùng nhóm bất kể tên tệp hay thứ tự.

Chưa xây: bộ sinh Kubernetes tổng quát (không cần cho giai đoạn này).

## 3. Mô hình coverage

Token dạng `chiều:giá trị` (xem `SEED_COVERAGE_REPORT.md`): kind workload, kind RBAC, loại subject, loại roleRef, API group/verb/resource của rule, danh sách container,
trường securityContext, cấu hình token SA, và **quan hệ giữa object** (`complete_chain`: workload chạy bằng SA được một binding cấp một Role có trong bundle; `cross_namespace_subject`; `multi_namespace`;
`binding_without_sa_object`). Một Pod đơn không tương đương một bundle đủ chuỗi: chiều `link` chính là phần đó. Chưa có chiều "control áp dụng được" vì phụ thuộc scanner: dùng `mr_applicability` (MR) và `config/control-registry.yaml`.

Giới hạn: token là điều kiện cần; một seed phủ token vẫn có thể không kích hoạt lỗi cụ thể (xem `MUTATION_GAP_ANALYSIS.md`).

## 4. Đề xuất triển khai tiếp (theo thứ tự tác động)

1. **Seed lấp token thiếu theo MR** (rẻ nhất, tác động lớn): thêm vào `seeds/synthetic/` các bundle có hai SA cùng tên khác namespace, subject User/Group, ClusterRole/ClusterRoleBinding, initContainers, automount. Chạy `seeds coverage` trước/sau để đo.
2. **Ghép bundle liên kết** từ KALM: với mỗi workload dùng `serviceAccountName`, tìm SA/Role/Binding *đã có trong corpus* khớp `(kind, namespace, name)`; chỉ ghép khi tham chiếu phân giải đúng; nếu thiếu thì báo `PARTIAL_BUNDLE`, không tự tạo object. Đo `complete_chain` tăng bao nhiêu.
3. **Chia development/evaluation cho nguồn ngoài mới** bằng `seeds split` và đóng băng trước khi xem output.
4. Sau 1–3: chạy lại RQ1 (applicability) với số seed duy nhất rõ ràng.

Chưa có dữ liệu để cam kết con số mở rộng; kế hoạch này không hứa tăng số phát hiện.
