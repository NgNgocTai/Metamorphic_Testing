# Taxonomy pattern V2: đánh giá KP1–KP3 bằng phương pháp phần tử template

Dữ liệu dưới đây sinh bằng `k8s-mr-lab mr patterns` (ma trận đầy đủ: `docs/MR_PATTERN_MATRIX.md`). Phương pháp lấy từ MST-wi: điền bảng
MR×phần tử, nhóm các MR có **cùng tổ hợp phần tử** (bài báo §8.2, Bảng 4). Khác biệt: từ vựng phần tử của K8s do mình định nghĩa
(`mrs/patterns.yaml: template_elements`), tương đương theo loại suy chứ không đồng nhất.

## 1. Năm khái niệm, không lẫn

| Khái niệm | Là gì | Ở đâu |
|---|---|---|
| Taxonomy R1–R10 | các **semantic variation points** của cấu hình Kubernetes (danh tính subject, quy tắc RBAC, loại container, ...) | kế hoạch KLTN; trường `category` của catalog |
| Security property | phát biểu ngữ nghĩa có trích dẫn | `mrs/security_properties.yaml` |
| Pattern KP1–KP3 | **cấu trúc MR** (loại quan hệ + loại biến đổi) | `mrs/patterns.yaml` |
| Phần tử template | đơn vị dựng pattern: `P-*`, `G-*`, `S-*`, `O-*` | `patterns.yaml: template_elements`; `template:` trong catalog |
| MR | phép biến đổi thực thi | `transforms/*.py` + `catalog.yaml` |
| Scanner control | cơ chế của SUT | `config/policy-mapping.yaml` |

## 2. Kết quả (7 MR)

| Nhóm theo phần tử | MR | Khai báo | Nhận xét |
|---|---|---|---|
| EP1 | MR-04, MR-06 | KP3 | **duy nhất** nhóm có ≥2 MR cùng tổ hợp (`P-STRUCT, P-VERDICT, G-MODIFY, S-TARGET, O-PASS-TO-FAIL`) |
| EP2 | MR-01 | KP1 | viết lại + `S-ALL` |
| EP3 | MR-02 | KP2 | thêm object + `P-REF` |
| EP4 | MR-03 | KP1 | viết lại + `P-STRUCT` |
| EP5 | MR-05 | KP3 | đổi trường + `P-CLOSED` + `O-FAIL-TO-PASS` |
| EP6 | MR-07 | KP1 | viết lại + `P-STRUCT, P-REF` |

## 3. Đánh giá

* **Các pattern có thật sự rút ra từ nhiều MR không?** KP3 (3 MR) và KP1 (3 MR: 01, 03, 07) có ≥2 thể hiện. KP2 chỉ 1 thể hiện (MR-02): nó là **giả thuyết pattern**, chưa phải pattern theo nghĩa MST-wi (pattern của họ có 12/23 chỉ 1 MR, nên hiện tượng này cũng có ở bài gốc).
* **Có chồng chéo/quá thô không?** Có: KP1 và KP3 **thô hơn** nhóm theo phần tử. KP1 gộp ba MR có tổ hợp khác nhau (khác `S-ALL`/`S-TARGET`, `P-STRUCT`/`P-REF`); KP3 gộp MR-05 (cần `P-CLOSED`, chiều `fail_to_pass`) với MR-04/06. Đây là bằng chứng tốt cho việc *không* gộp thêm abstract class.
* **Mức abstraction phù hợp?** Code chung chỉ có ở: `ControlledChange` (3 MR: 04, 05, 06: cùng "đúng một thay đổi tại một path") và `PerCandidateMR` (03, 04, 05, 06). KP1 không có code chung vì bất biến khác nhau (parsed content / permission tuples / hình dạng RoleBinding); thêm MR-07 là thể hiện thứ ba nhưng **vẫn** là bất biến thứ ba ⇒ không có cơ sở để trừu tượng hóa.
* **Overengineering?** Không có thêm lớp nào cho KP1/KP2. Rủi ro còn lại: lưu `template:` trong catalog thêm một trường phải bảo trì; đổi lại `mr patterns`/`mr validate` kiểm từ vựng và suy ra pattern, và bảng này tính lại được.
* **Ba-MR-trở-lên cho thấy điều gì?** Khi MR-07 được thêm, bảng xác nhận *không* có nhóm EP mới trùng nhóm cũ; pattern "viết lại" chưa hội tụ.

## 4. Quy tắc thêm pattern / base class

1. Pattern mới chỉ khi ≥2 MR có cùng tổ hợp phần tử **và** cùng lý do chứng minh (`proof_obligation`).
2. Base class mới chỉ khi ≥2 MR thật sự dùng chung *một thuật toán* (không chỉ chung metadata).
3. `mr patterns` chạy lại sau mỗi MR mới; nếu một nhóm EP có ≥2 MR mà các MR vẫn viết lại cùng logic, mới cân nhắc trừu tượng hóa.

## 5. Điều chưa biết

Với 7 MR, mọi kết luận về "pattern" là mô tả, không phải thống kê. Số phần tử và tên phần tử có thể thay đổi khi thêm domain khác
(NetworkPolicy, Pod Security thêm trường). Bảng phần tử là đề xuất của khóa luận, chưa qua review độc lập.
