# Ma trận yêu cầu → MR (giai đoạn 1 của PoC)

Dữ liệu gốc: `mrs/requirements.yaml` cho yêu cầu, `mrs/catalog.yaml` (`requirements`, `origin`) cho liên kết MR ↔ yêu cầu; trạng thái COVERED/PARTIAL được suy ra, không gõ tay (kiểm bằng `k8s-mr-lab mr requirements`). Bốn nguồn: OWASP K8s Top 10 2025 (chọn nhóm rủi ro), MITRE CWE (phân loại cấu hình bị cấm),
tài liệu Kubernetes chính thức (yêu cầu cụ thể và ngữ nghĩa), control của Trivy/Kubescape đã pin (scanner nói nó kiểm gì). CIS, NSA/CISA, ATT&CK: ngoài phạm vi PoC (để dành cho related work).

Quy trình: nhóm rủi ro (K01, K02) → **yêu cầu cụ thể** (trích nguyên văn) → phân tích ngữ nghĩa và hợp đồng control → thiết kế MR (precondition, transformation, relation, scope) → kiểm chứng → *sau đó mới* phân loại pattern.
Không giới hạn trước vào KP1–KP3: MR-09 cho một tổ hợp phần tử mới nên sinh ra pattern KP4 (giả thuyết, 1 thể hiện).

## Ma trận (N = 10; K01: 5, K02: 5)

| Yêu cầu | Nhóm | Nguồn (trích nguyên văn trong YAML) | CWE | Control (Trivy / Kubescape) | Trạng thái (suy ra từ catalog) | MR | Nguồn gốc MR (`origin` trong catalog) |
|---|---|---|---|---|---|---|---|
| R01 privileged bị cấm | K01 | PSS Baseline, Privileged Containers | CWE-250 | KSV-0017 / C-0057 | COVERED | MR-04 | retrospective |
| R02 không chia sẻ host namespaces | K01 | PSS Baseline, Host Namespaces | CWE-668 | KSV-0009/0010/0008 / C-0041 | PARTIAL | MR-06 (chỉ hostNetwork) | retrospective |
| R03 hostPath bị cấm | K01 | PSS Baseline, HostPath Volumes | CWE-668 | KSV-0023 / C-0048 | DERIVABLE_NOT_IMPLEMENTED | | |
| R04 hostPort | K01 | PSS Baseline, Host Ports | CWE-668 | KSV-0024 / C-0044 | DERIVABLE_NOT_IMPLEMENTED | | |
| R05 capabilities | K01 | PSS Baseline, Capabilities | CWE-250 | KSV-0022, KSV-0005 / C-0046 | NOT_FEASIBLE (`CONTRACT_NOT_READ`) | | |
| R06 RoleBinding trong namespace của nó | K02 | RBAC docs | CWE-269 | (Trivy không quan sát được) / C-0267, C-0272 … | COVERED | MR-02 | empirical |
| R07 tránh wildcard | K02 | RBAC Good Practices | CWE-732 | KSV-0044/0045/0046/0112 / C-0035 | DERIVABLE_NOT_IMPLEMENTED | | |
| R08 get/list/watch Secrets đều lộ nội dung | K02 | RBAC Good Practices, Listing secrets | CWE-200 | KSV-0113 / C-0015 | **COVERED** | **MR-09** | **prospective** |
| R09 cấp quyền ở mức namespace | K02 | RBAC Good Practices | CWE-269 | (không có control) | NOT_FEASIBLE (`RELATION_NOT_SUPPORTED`) | | |
| R10 không bind `system:masters` | K02 | RBAC Good Practices | CWE-269 | KSV-0123 / C-0246 | DERIVABLE_NOT_IMPLEMENTED | | |

CWE đều là phán đoán chọn lớp điểm yếu (ID và tiêu đề đã kiểm tại cwe.mitre.org: 250, 269, 668, 732, 200); chúng phân loại *cấu hình bị cấm*, không gắn nhãn lỗi scanner.

## Tỉ lệ X/N (đọc kèm điều kiện)

| | Số | Ghi chú |
|---|---|---|
| Có MR đầy đủ | **3/10** | R01, R06 (cũ) + R08 (**dẫn xuất mới**) |
| Có MR một phần | 1/10 | R02 |
| Có thể dẫn xuất, chưa cài | 4/10 | R03, R04, R07, R10 (đã có control, chưa viết MR) |
| Chưa khả thi | 2/10 | R05 (chưa đọc danh sách capability của scanner), R09 (cần quan hệ monotone) |

**Điều không được hiểu từ bảng:**
* "Có MR" = MR tồn tại và qua cổng **cấu trúc**. Chưa MR nào được review độc lập, chưa MR nào có đánh giá độc lập.
* **R01, R02, R06 là MR cũ chỉ được gắn nhãn vào yêu cầu sau khi đã tồn tại** (MR-04/06 viết theo trực giác, MR-02 từ hiện tượng K1). Điền chúng vào ma trận **không** chứng minh chúng được dẫn xuất từ OWASP; cột "nguồn gốc MR" ghi `retrospective`/`empirical` (trước đây ghi `pre_existing`) để không lẫn.
* Chỉ **R08 → MR-09** đi đúng chuỗi yêu cầu → MR (walkthrough: `MR_DERIVATION_WALKTHROUGH_MR09.md`).
* MR-01, MR-03, MR-05, MR-07, MR-08 **không** thuộc 10 yêu cầu này (yêu cầu tương ứng không nằm trong danh sách, hoặc MR không gắn với yêu cầu nào): `mr requirements` liệt kê chúng.

## Các lớp lý do "chưa khả thi" (cố định)

`NO_CONTROL_CONTRACT` (không control nào nói kiểm thuộc tính đó) · `RELATION_NOT_SUPPORTED` (cần quan hệ checker chưa có) · `CONTRACT_NOT_READ` (control tồn tại nhưng danh sách/hợp đồng chưa đọc nên chưa phát biểu được quan hệ).
Đây là kết quả hợp lệ của quy trình (tương đương việc bài MST-wi ghi rõ yêu cầu nào MT không áp dụng được), không phải thất bại.

## Mở rộng

Thêm yêu cầu = thêm một mục vào YAML và điền trạng thái; `mr requirements` kiểm tính nhất quán với catalog (MR có tồn tại, trạng thái có MR phải có MR, lý do hợp lệ, trích dẫn không rỗng). Danh sách R03, R04, R07, R10 là hàng đợi dẫn xuất kế tiếp; mỗi mục đã có control đã đọc tiêu đề/kind, cần đọc hợp đồng trước khi nêu quan hệ.
