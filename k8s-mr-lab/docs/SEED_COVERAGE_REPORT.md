# Báo cáo coverage seed (2026-11-01)

Sinh bằng `k8s-mr-lab seeds coverage ... --with-mr` (tất định, không scanner). Dữ liệu thô: `docs/evidence/archive/seed_coverage_2026-11-01/*.json`.
Từ vựng 52 token được khai báo cố định trong `src/k8s_mr_lab/seeds.py` **trước** khi đo corpus nào; coverage = token phủ / token định nghĩa.
Token là điều kiện cần cho kiểm thử có nghĩa, không phải bằng chứng seed phát hiện được lỗi.

## 1. Seed của dự án

| | Số |
|---|---|
| Thư mục seed | 8 (6 tổng hợp, 1 lịch sử, 1 candidate) |
| Hợp lệ | 7 (`invalid-missing-role` cố ý hỏng, bị loại) |
| Trùng nội dung | 1 (`K1-role-namespace` = `rbac-workload`) |
| **Seed duy nhất hợp lệ** | **6** |
| Token phủ | **17 / 52 (33%)** |

Các tài liệu cũ nói "8 seed"; số đúng để đếm độ đa dạng là **6**.

| Chiều | Phủ | Thiếu |
|---|---|---|
| workload (7) | 2 | ReplicaSet, DaemonSet, StatefulSet, Job, CronJob |
| rbac_kind (5) | 3 | **ClusterRole, ClusterRoleBinding** |
| subject_kind (3) | 1 | **User, Group** |
| roleref_kind (2) | 1 | ClusterRole |
| rule_api_group (5) | 1 | apps, rbac.authorization.k8s.io, wildcard, other |
| rule_verb (8) | 3 | create, update, patch, delete, wildcard |
| rule_resource (6) | 2 | pods, rbac, wildcard, other |
| container_list (3) | 1 | initContainers, ephemeralContainers |
| security_context (7) | 2 | privileged_true, host_network_true, host_pid_true, run_as_non_root_true, read_only_root_fs_true |
| sa_token (2) | 0 | automount_true, automount_false |
| link (4) | 1 | binding_without_sa_object, **cross_namespace_subject**, **multi_namespace** |

Áp dụng MR (static) trên 6 seed duy nhất: MR-01 6/6 · MR-02 3/6 · MR-03 **1/6** · MR-04 4/6 · MR-05 **1/6** · MR-06 1/6 · MR-07 3/6.
Các chiều đậm là những vùng mà thí nghiệm mutant chỉ ra (đột biến về namespace của subject không bao giờ được kích hoạt).

## 2. Corpus KALM cục bộ (RQ1: khả năng áp dụng trên nguồn bên ngoài)

Provenance: thư mục `Kalm-Benchmark/manifests` trên máy, commit local `300dca1` (2026-09-21), 238 manifest (không kể tệp `_*`). PoC dùng commit `dac3df5`;
mình đã so sha256 của **65 tệp PoC đã chọn** với bản này: **trùng 65/65** sau khi chuẩn hóa CRLF⇒LF. Với 173 tệp còn lại chưa so được.

| | Số |
|---|---|
| Manifest | 238 (236 hợp lệ, 2 không nạp được) |
| Trùng nội dung | 0 |
| Token phủ | **40 / 52 (77%)** |

Phủ rất rộng ở từng chiều (RBAC kinds 5/5, subject kinds 3/3, verbs 8/8, security_context 7/7, sa_token 2/2), nhưng:

| MR | Áp dụng được trên (236 seed) | Ghi chú |
|---|---|---|
| MR-01 | 236 | biểu diễn |
| MR-04 | 130 | privileged false tường minh |
| MR-06 | 131 | hostNetwork false tường minh |
| MR-02 | **3** | cần RoleBinding→Role cục bộ + SA |
| MR-05 | **3** | |
| MR-07 | **3** | |
| MR-03 | **2** | |

* **`link:complete_chain` = 0 trên toàn corpus**, `multi_namespace` = 0, `cross_namespace_subject` = 0. KALM mỗi tệp là một cấu hình lỗi đơn lẻ, gần như không có chuỗi workload→SA→binding→Role đầy đủ.
* Hệ quả cho RQ1: **các MR cấp subject gần như không có đầu vào từ benchmark bên ngoài.** Muốn đánh giá chúng cần *ghép bundle liên kết* (xem `SOURCE_INPUT_GENERATION_V2.md`), không phải thêm manifest.
* Con số này là về *khả năng áp dụng*, không về phát hiện lỗi.

## 3. Việc cần làm (xếp theo tác động)

1. Seed tổng hợp lấp các token thiếu **có chủ đích theo MR**: hai SA cùng tên khác namespace (MR-08), subject `User`/`Group`, ClusterRole + ClusterRoleBinding, `initContainers`, `automountServiceAccountToken`.
2. Bộ ghép bundle liên kết từ manifest KALM (workload từ file này + Role/Binding từ file kia) với kiểm tra tham chiếu, **không** ghép theo tên.
3. Khi có nguồn mới (Helm chart đã render, ISSTA benchmark): chạy `seeds inventory/coverage`, gán phân vùng `EXTERNAL`, chia bằng `seeds split` **trước** khi xem kết quả scanner.
