# Báo cáo refactor xây dựng MR (nhánh `research/mr-patterns`, từ tag `poc-v1.0.0`)

## 1. Bảo toàn PoC

| Kiểm tra | Kết quả |
|---|---|
| Unit tests trước refactor | 80 passed, 3 skipped |
| Unit tests sau refactor (Windows) | 111 passed, 3 skipped (31 test mới; 1 test cũ sửa, xem 4) |
| Toàn bộ test trong WSL với Trivy 0.75.0 + Kubescape v4.0.15 thật | **114 passed, 0 skipped** (3 integration test chạy trên scanner thật) |
| Chạy lại pipeline thật trên toàn bộ seed (`run --scanner trivy|kubescape`, 2026-11-01) so với run PoC đã lưu (`runs/trivy`, `runs/kubescape`) | **Trivy 41/41 dòng, Kubescape 41/41 dòng giống hệt** (kết quả MR, verdict nguồn/follow-up, trạng thái cặp, lý do skip, sha256 văn bản source và follow-up). Tái lập bằng `scripts/compare_runs.py`; bản lưu: `docs/evidence/mr_patterns_verification/` |
| `tests/golden`, scanner pins và seed PoC so với `poc-v1.0.0` | Giữ nguyên; `config/policy-mapping.yaml` bổ sung control/mapping MR-06 và `seeds/candidate/pod-hostnet` là seed DEV mới, nằm ngoài tập seed PoC |
| Fingerprint hành vi MR-01..05 trên 7 seed (applicable, tham số, trace, sha256 follow-up, pair status, targets, mapping, relation) | **Giống hệt** (`scripts/snapshot_mr_behavior.py`; baseline: `docs/baseline/mr_behavior_poc_v1.json`, 28 case) |
| Chưa chạy | `capture_golden.py` (ghi đè golden nên cố ý không chạy; chỉ kiểm import). Chạy lại triage/minimize để tái hiện reproducer K1/N2: không chạy, nhưng họ K1 vẫn xuất hiện nguyên vẹn (5 VIOLATION Kubescape giống hệt PoC) |

Fingerprint chứng minh *sinh follow-up và kiểm tra cặp* không đổi; hai lần chạy scanner thật ở trên chứng minh *kết quả scan và phán định MR* không đổi trên 41+41 phép so sánh. Hai run này dùng `mapping_digest` cũ (`d36741f032`), tức là trước khi thêm mapping MR-06. Phạm vi kết luận: 8 seed hiện có, hai scanner đã pin; không suy rộng sang seed khác.

## 2. Thay đổi

| File | Thay đổi | Lý do |
|---|---|---|
| `transforms/base.py` | `@implements`, `bind(spec)`; bỏ metadata khai báo ở class | 1 nguồn metadata (H1) |
| `transforms/__init__.py` | Tự import mọi module | Không còn sửa `registry.py` khi thêm MR (H6) |
| `transforms/patterns.py` (mới) | `PerCandidateMR`, `ControlledChange`, `Change` | Trùng lặp thật ở MR-03/04/05 (H2) |
| `transforms/pod_privileged.py`, `rbac_api_group.py`, `rbac_split_verbs.py` | Dùng pattern; logic giữ nguyên | |
| `transforms/rbac_decoy_role.py`, `yaml_reorder.py` | Chỉ bỏ metadata trùng, thêm decorator | Logic riêng, không đụng |
| `transforms/pod_host_network.py` (mới) | MR-06 candidate | Ví dụ quy trình mới |
| `validation.py` | `expect_single_change` (so chặt kiểu) | Dùng chung MR-04/05; sửa `1 == True` |
| `k8s.py` | `workloads_of_service_accounts` | Block trùng MR-03/05 |
| `registry.py` | Schema catalog, id trùng, status, `active_mrs`, bỏ danh sách class | |
| `checker.py` | Bảng `RELATIONS` (đăng ký predicate tùy chỉnh); bỏ import vòng | |
| `runner.py`, `cli.py` | Chọn MR qua `active_mrs` (candidate cần `--mr` tường minh) | |
| `mr_tools.py` (mới) + `cli.py` | `mr list / validate / trace / scaffold` | Gate và quy trình thêm MR |
| `mrs/security_properties.yaml`, `mrs/patterns.yaml` (mới); `mrs/catalog.yaml` | Property, pattern, `pattern`/`property_id`/`all_failures`, MR-06 | Truy vết |
| `docs/*`, `scripts/snapshot_mr_behavior.py`, `tests/unit/test_mr_framework.py` | Tài liệu, fingerprint, test | |

Giữ nguyên: toàn bộ `scanners/`, `normalize/`, `bundles.py`, `report.py`, `triage.py`, ngữ nghĩa ba quan hệ checker và mapping MR-01..05. `policy-mapping.yaml` bổ sung control/mapping MR-06; các control mới cũng được normalizer đọc qua registry `controls`.

## 3. Trước/sau (đo thực tế)

| Chỉ số | Trước | Sau | Nhận xét trung thực |
|---|---|---|---|
| Dòng 5 file MR | 338 | 285 (−53, −16%) | |
| Dòng hạ tầng MR (`base` + `patterns`) | 47 | 124 | **+77** |
| Tổng (MR + hạ tầng) cho 5 MR | 385 | 409 | **Tăng 24 dòng**: với 5 MR, abstraction chưa lời về số dòng |
| MR thứ 6 cùng KP3 | ~62 dòng (cỡ MR-04 cũ) | 38 dòng (MR-06) | Lợi ích xuất hiện từ MR KP3 thứ ba trở đi |
| Metadata khai báo hai nơi | 4 trường × 5 MR | 0 | |
| Chỗ phải sửa để thêm MR | transform + `registry.py` (2 chỗ) + catalog + mapping + test | transform + catalog + test (+ property mới, + mapping khi đã xác minh) | `registry.py`, `runner.py`, `checker.py` không còn phải sửa |
| Truy vết MR → property → nguồn | Không | 6/6 MR | Chỉ tham chiếu `verified: true` là bằng chứng; xem ma trận |
| Gate tự động trước khi chạy scanner | Không | `mr validate` (chạy MR trên mọi seed) | |
| Biểu diễn MR phức tạp | Python | Python (không đổi) | Cố ý không đưa vào YAML |

Kết luận: giá trị chính là **truy vết, gate và bớt chỗ đăng ký**, không phải giảm số dòng. Chưa có bằng chứng thiết kế mới
"tốt hơn" ngoài các chỉ số trên; chỉ MR-06 làm phép thử, và nó chỉ chứng minh tính tiện, không chứng minh khả năng bắt lỗi.

## 4. Tương thích và điều cần biết

- Chuỗi `reason` của `INVALID_PAIR` ở MR-04/05 đổi (ví dụ `change_is_not_False_to_True` thay cho tên riêng); chỉ xuất
  hiện ở cặp không hợp lệ. Không test hay evidence PoC nào phụ thuộc vào chúng (đã grep).
- `provenance.json: mr_spec_digest` của các run **mới** khác run PoC vì spec có thêm trường. Evidence cũ vẫn hợp lệ
  cho tag `poc-v1.0.0`; không so digest chéo hai giai đoạn.
- Class MR tạo trực tiếp (`PrivilegedFlip()`) vẫn dùng được cho `transform/targets`, nhưng `name/relation/...` chỉ có sau
  `load_catalog` (script `capture_golden.py` chỉ cần phần đầu).
- `test_catalog_matches_code` được sửa: vẫn khẳng định đúng 5 MR PoC không-candidate, thêm MR-06. Không sửa golden.
- Validator MR-04 từng chấp nhận `privileged: 1`; nay từ chối (cặp do MR sinh ra không bao giờ có giá trị đó).

## 5. MR-06 trên scanner thật (bằng chứng phát triển, không phải đánh giá độc lập)

Control đọc từ chính policy bundle đã pin: Trivy **KSV-0009** (`host_network.rego`, kind Pod/ReplicaSet/Deployment/StatefulSet/DaemonSet/CronJob/Job…)
và Kubescape **C-0041** (`host-network-access`, Pod + Deployment/ReplicaSet/DaemonSet/StatefulSet + Job/CronJob). Seed riêng
`seeds/candidate/pod-hostnet` (đặt ngoài `seeds/synthetic` để không đổi baseline).

| Scanner | Kết quả | Verdict nguồn | Verdict follow-up |
|---|---|---|---|
| Trivy 0.75.0 | PASS (`pass_to_fail`) | **PASS suy luận** (`pass_inferred`, không có FAIL gắn vào resource) | FAIL, line=6 |
| Kubescape v4.0.15 | PASS (`pass_to_fail`) | PASS tường minh | FAIL |

n = 1 seed × 1 cặp mỗi scanner, tác giả thiết kế seed và MR cùng lúc, nên đây là DEV evidence. MR-06 **giữ `candidate`**: nâng lên
`mvp_conditional` sẽ đưa MR-06 vào mọi run mặc định (thêm hàng SKIP cho từng seed), làm lệch so sánh với baseline PoC. Quyết định
này cần chốt cùng giảng viên cùng với việc có chạy held-out hay không.

## 6. Tham chiếu đã xác minh (2026-11-01)

| Tham chiếu | Nguồn đã đối chiếu |
|---|---|
| CWE-250 *Execution with Unnecessary Privileges*; CWE-269 *Improper Privilege Management* | cwe.mitre.org/data/definitions/250.html, /269.html (đối chiếu ID và tiêu đề; **gán CWE cho MR là phán đoán chọn miền**) |
| MR-05: core group là `apiGroups: [""]`, Secrets thuộc nhóm đó | Ví dụ Role/ClusterRole `secret-reader` trong tài liệu Kubernetes RBAC |
| MR-01: thứ tự khóa mapping không có nghĩa | YAML 1.2.2 §3.2.1.1 và §3.2.2.1 |
| CIS 5.2.5 (host network) | Nhãn trong framework `cis-v1.12.0` của Kubescape đã pin; **tài liệu CIS không được đọc**, số mục khác nhau giữa các phiên bản benchmark |

Chưa điền: NSA/CISA, ATT&CK, và CIS cho các control còn lại (không tìm thấy nhãn trực tiếp trong artifact; không đoán).

## 7. Hạn chế và việc tiếp theo

1. Đánh giá độc lập MR mới (held-out, known-defect) chưa làm: thuộc WP5, cần chốt với giảng viên.
2. MR-06 mới có DEV evidence, nguồn Trivy là PASS suy luận; giữ `candidate`.
3. KP1, KP2 chưa có code chung vì chưa đủ 2 thể hiện cùng validator; xét lại khi có MR thứ ba.
4. `runner.run_pair` dài nhưng không tách (xem Audit 3.3).
5. Chưa chạy `mr validate` trong CI; `docs/MR_TRACEABILITY.md` sinh tay bằng `mr trace`.
6. Chưa chạy lại triage/minimize và ablation probes sau refactor (kết quả run đã giống hệt, nên rủi ro thấp, nhưng chưa kiểm).
