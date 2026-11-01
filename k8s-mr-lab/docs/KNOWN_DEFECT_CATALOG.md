# Danh mục lỗi scanner đã biết (known-defect catalog)

Chỉ ghi những gì **đã đọc từ nguồn chính thức** (GitHub API công khai, 2026-11-01). Mọi trường chưa kiểm được ghi `UNVERIFIED`.
Phạm vi tìm kiếm **chưa đầy đủ**: một số truy vấn bị giới hạn tốc độ của GitHub (API chưa xác thực) và chưa quét Trivy kỹ. Đây là danh mục khởi đầu, không phải khảo sát toàn diện.

Thang trạng thái: `LEAD → SOURCE_VERIFIED → REPRODUCIBLE → ELIGIBLE_FROZEN → ADJUDICATED`. Hiện **0 mục `ELIGIBLE_FROZEN`**.

## 1. Mục đã đọc

### KD-001: Kubescape `AggregateResourcesBySubjects` ghép roleRef xuyên namespace

| Trường | Giá trị |
|---|---|
| Issue | https://github.com/kubescape/kubescape/issues/2579 (closed 2026-07-31, nhãn `bug`) |
| Sửa | https://github.com/kubescape/opa-utils/pull/177 "fix(reporthandling): resolve roleRef within the binding's own namespace" (merged 2026-07-31) |
| Thành phần | `reporthandling/regoresourcesaggregator.go` (repo `opa-utils`), không phải rego của control |
| Mô tả (đã đọc) | ghép binding–Role chỉ theo `roleRef.kind + name`, không so namespace và không kiểm loại binding tương thích; 17/19 rule dùng `resourcesAggregator: subject-role-rolebinding` bị ảnh hưởng |
| Phiên bản bị lỗi | **Kubescape v4.0.11** dùng `opa-utils v0.0.301` (không chứa bản sửa); từ v4.0.10 → v0.0.300 cũng trước sửa. Nguồn: `go.mod` tại tag + `git merge-base --is-ancestor` |
| Phiên bản chứa bản sửa | **Kubescape v4.0.12 trở đi** (`opa-utils v0.0.303` ≥ `v0.0.302`, tag đầu tiên chứa merge commit `83ec3801`); v4.0.13–v4.0.15 dùng `v0.0.312` |
| Control liên quan | các control dùng aggregator: trong phạm vi MR hiện có là `C-0015`, `C-0007`, `C-0035`, `C-0053` |
| Chế độ quét | **local-file xác nhận ảnh hưởng** (tái hiện bằng `kubescape scan framework allcontrols <dir>` ở v4.0.11) |
| Reproducer | bundle MR-02 (Role cùng tên ở namespace khác, không bind): `docs/KD001_REPRODUCTION.md` |
| MR khả dĩ | MR-02 |
| Quan sát | v4.0.11: control aggregator `C-0015/0007/0035` chuyển PASS → FAIL trên `ServiceAccount` và `RoleBinding` ở 7/8 cặp MR-02; v4.0.12 và v4.0.15: không (cùng artifacts, cùng sha256 đầu vào, 28/114 khóa khác nhau) |
| Phân vùng | liên quan họ lỗi K1 đã định hình MR-02 ⇒ **không** vào mẫu số độc lập |
| Trạng thái | **`REPRODUCIBLE`** (bản lỗi v4.0.11 vs bản sửa v4.0.12, binary khớp checksum chính thức). Vẫn là ca **DEV** (cùng lớp lỗi dẫn dắt MR-02), chưa `ELIGIBLE_FROZEN` |

Quan hệ với K1 của PoC: K1 nằm ở rego tự join của `C-0267/C-0272` (không đi qua aggregator). Cùng lớp lỗi (ghép roleRef theo tên), **chưa chứng minh cùng nguyên nhân**.

## 2. Lead chưa đọc kỹ (không phải ground truth)

| Issue | Tiêu đề (từ API) | Vì sao chưa nhận |
|---|---|---|
| kubescape#3144 (closed 2026-08-14) | C-0261 thiếu trong `wholeClusterControlIDsFallback`, lọt PASS khi binding SA xuyên namespace trên cụm lớn/streaming | liên quan chế độ quét cụm/streaming, không phải local-file; cần kiểm |
| kubescape#2871 (closed 2026-08-09) | quét lớn/streaming bỏ lọt control khi object nằm ở nhiều namespace | cùng lý do; tên `C-0267` xuất hiện trong danh sách fallback |
| kubescape#3069 (closed 2026-08-12) | RBAC bị hạn chế ⇒ 403 bị coi là thiếu dữ liệu | chế độ cụm |
| kubescape#4071 (open 2026-10-07) | đề xuất differential testing với ngữ nghĩa K8s upstream | liên quan phương pháp (so với kube-apiserver), không phải lỗi; **đọc làm related work** |
| kubescape#4053 | resolve ServiceAccount subject không có namespace trong namespace của RoleBinding | liên quan `rbacgraph`/MCP; **chưa xác minh** có nằm trên đường `kubescape scan` |

## 3. Chưa tìm thấy

* Issue/PR của Kubescape về `C-0267`/`C-0272` join Role theo tên (K1): truy vấn chưa thấy; **không có nghĩa là chưa ai báo**.
* Issue của Trivy/`trivy-checks` về KSV-0113 bỏ qua `apiGroups` (N2): truy vấn chưa thấy; cần tra thủ công.
* Subject dạng `User` không được `C-0267` xử lý (MR-07): chưa thấy báo cáo.

## 4. Quy tắc để một mục thành mẫu số độc lập

1. Có issue/PR chính thức đã đọc, mô tả lỗi và component.
2. Xác định được phiên bản có lỗi **và** phiên bản đã sửa bằng nguồn (release notes, `go.mod`, tag), không đoán từ ngày.
3. Có reproducer thành bundle chạy được, đúng chế độ `local-file`, và tái hiện trên bản lỗi (và hết trên bản sửa nếu có binary).
4. Chưa dùng để thiết kế MR (K1/N2/KD-001 đều đã dùng ⇒ `DEV/REGRESSION`).
5. Chốt trước khi xem kết quả MT.
KD-001 đạt 2–3 nhưng không đạt 4 (đã dẫn dắt MR-02); vì vậy vẫn **không có tỉ lệ phát hiện lỗi đã biết** nào được tính. Cần thêm ít nhất một lỗi độc lập.

**Bài học từ KD-001:** MR-02 với phạm vi so sánh cũ *không* phát hiện nó; chỉ phạm vi mở rộng (ServiceAccount, RoleBinding) mới phát hiện. Phạm vi mở rộng nay là phạm vi chính thức duy nhất của MR-02 (khung thống nhất). Xem `KD001_REPRODUCTION.md`.
