# Mở rộng framework: thêm một MR, một scanner control hoặc một scanner

Tiền đề: `UNIFIED_FRAMEWORK.md`; phương pháp dẫn xuất ở `../MR_DERIVATION_METHODOLOGY.md` và `../SECURITY_PROPERTY_DERIVATION_GUIDE.md`. Mọi lệnh chạy từ thư mục `k8s-mr-lab/`; bước 1–6 **không cần scanner**.

## Thêm một MR (một cách duy nhất)

Phần phải viết: **(a)** một mục catalog, **(b)** một class MR, **(c)** entry mapping (hoặc lý do `unsupported`), **(d)** test. Không sửa `runner.py`, `checker.py`, `cli.py`, `normalize/`, `report.py`, `informative.py`.

```bash
k8s-mr-lab mr list
k8s-mr-lab mr scaffold MR-10 host-pid-flip --pattern KP3   # khung code theo pattern + stub catalog (có đủ trường của khung)
```

1. **Yêu cầu và property.** Chọn/thêm yêu cầu trong `mrs/requirements.yaml` (quote nguyên văn từ tài liệu chính thức) và property trong `mrs/security_properties.yaml` (mỗi tham chiếu có `verified: true|false`; không điền số mục CIS/CWE chưa kiểm).
2. **Catalog** (`mrs/catalog.yaml`, `status: candidate`): các trường cũ cộng `origin`, `requirements: [{id, coverage}]`, `touches`, `targets`. Quy tắc: `prospective`/`retrospective` phải có yêu cầu; `touches` là kind bị đổi (`workload` cho nhóm workload); `targets` là các selector mà `targets()` sẽ trả. Chọn `pattern` và `template` ở `mrs/patterns.yaml` (`mr patterns` cho biết MR rơi vào nhóm nào).
3. **Implementation** (`src/k8s_mr_lab/transforms/<tên>.py`): `@implements("MR-10")`. KP3 (đổi đúng một trường) chỉ cần `candidates`, `candidate_params`, `transform`, `expected_change`, `targets`; các pattern khác kế thừa `MetamorphicRelation` và tự cài `validate_pair`. Logic tìm target và biến đổi riêng của MR nằm trong class này. Tùy chọn `rule_probe = (khóa, regex)` để triage chỉ ra chỗ rego nhắc tới trường bị đổi.
4. **Mapping** (`config/policy-mapping.yaml`): chỉ sau khi đọc control của **đúng phiên bản pin**. Mỗi scanner: danh sách `{control, target, reason, role}` hoặc một dòng trong `unsupported` có lý do. Nếu control mới chưa có trong registry, sinh lại registry (mục dưới); không chép kind của control vào mapping.
5. **Test**: một positive, một counterexample (precondition từ chối hoặc `INVALID_PAIR`), "source không bị sửa". Mẫu: `tests/unit/test_mr_framework.py` (MR-06) và MR-10 tạm trong `tests/unit/test_unified_framework.py`.
6. **Cổng cấu trúc**: `k8s-mr-lab mr validate` kiểm schema, truy vết (pattern/property/requirement), **mapping và scope** (mục 3 của `UNIFIED_FRAMEWORK.md`) rồi chạy MR trên mọi seed hợp lệ (transform không sửa source, xác định, cặp hợp lệ, `targets()` chỉ trả selector đã khai báo). Không chứng minh MR đúng về ngữ nghĩa: hoàn thành `../MR_SEMANTIC_REVIEW_CHECKLIST.md`.
7. **Chạy thật**: `k8s-mr-lab run --scanner trivy --seeds seeds/synthetic --mr MR-10 --out runs/x`, rồi `triage`. Đọc `comparisons.csv` (có `role`, `tier`, `basis`, `engaged`), không chỉ `results.csv`. Seed cho candidate đặt trong `seeds/candidate/<tên>/`. Đổi `status` thành `mvp_conditional` khi xong.
8. `k8s-mr-lab mr trace --out docs/MR_TRACEABILITY.md` và `k8s-mr-lab mr requirements`.

## Thêm một scanner control vào phạm vi

1. Thêm entry vào `policy-mapping.yaml` (control, target, reason, role).
2. Sinh lại registry từ policy đã pin: `scripts/derive_control_registry.py --trivy-policies <dir> --kubescape-artifacts <dir> --trivy-policy-digest <digest> --kubescape-policy-digest <digest> --out config/control-registry.yaml` (digest lấy từ `k8s-mr-lab versions`).
3. `mr validate`: control phải quan sát được thay đổi (nếu là đối chứng âm thì phải **không** quan sát được).

## Thêm một scanner

Thêm lớp trong `scanners/` (execute, version, policy_digest), một normalizer trong `normalize/`, phần ghim trong `config/scanners.yaml`, và cột scanner trong registry/mapping. Runner, checker, report không đổi.

## Kiểm tra kiến trúc

`pytest tests/unit/test_unified_framework.py` phải xanh: nó chặn hardcode id MR/control trong core, đường chạy thứ hai, và mọi mapping mồ côi hoặc gán vai trò sai.
