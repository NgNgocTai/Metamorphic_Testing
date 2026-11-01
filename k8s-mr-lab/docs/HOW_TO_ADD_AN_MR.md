# Thêm một MR mới

Tiền đề: đọc `MR_DERIVATION_METHODOLOGY.md` §3. Mọi lệnh chạy từ thư mục `k8s-mr-lab/`; **không cần scanner** cho
bước 1–6.

```bash
k8s-mr-lab mr list                       # xem catalog, pattern, scanner đã ánh xạ
k8s-mr-lab mr scaffold MR-07 host-pid-flip --pattern KP3   # khung code theo pattern (KP3: ControlledChange; KP1/KP2: tự cài) + stub catalog
# scaffold từ chối id sai định dạng/đã tồn tại và pattern lạ. Vì transforms/ được import cả thư mục, sau scaffold phải
# thêm ngay mục catalog; nếu chưa, load_catalog() báo 'implemented but missing from catalog'.
```

1. **Property.** Thêm (hoặc chọn) mục trong `mrs/security_properties.yaml`. Mỗi tham chiếu phải có `verified: true|false`.
   Không điền số mục CIS/CWE chưa kiểm.
2. **Pattern.** Chọn trong `mrs/patterns.yaml`. KP3 (đổi đúng 1 trường) chỉ cần viết 4 hàm:
   `candidates` (precondition), `candidate_params`, `transform`, `expected_change` (+ `targets`). Validator cặp, quy tắc
   "đúng 1 thay đổi", so sánh chặt kiểu đã có trong `ControlledChange`. Với KP1/KP2 hoặc MR có ngữ nghĩa phức tạp,
   kế thừa `MetamorphicRelation` và tự cài `validate_pair` (xem MR-01/02/03). Không cố nhét vào YAML.
3. **Catalog.** Thêm mục vào `mrs/catalog.yaml` với `status: candidate`, `pattern`, `property_id`, `relation`,
   `preconditions`, `pair_checks`, **`counterexample`**, `limits`. Metadata chỉ ở đây; class chỉ có
   `@implements("MR-07")`. Không đăng ký ở đâu khác (không sửa `registry.py`, `runner.py`, `checker.py`).
4. **Test.** Một positive, một counterexample (precondition từ chối hoặc `INVALID_PAIR`), và "source không bị sửa".
   Mẫu: `tests/unit/test_mr_framework.py` (MR-06).
5. **Cổng cấu trúc (structural gate).** `k8s-mr-lab mr validate` kiểm schema (kiểu dữ liệu từng trường), truy vết (pattern/property
   tồn tại, relation và base class hợp pattern, mapping đủ `control`/`target`), rồi **chạy MR trên mọi seed hợp lệ**
   (seed INVALID_SOURCE bị bỏ qua và được liệt kê): transform không sửa source, xác định, cặp hợp lệ, target trong mapping có
   tồn tại. Lệnh này **không** chứng minh MR đúng về ngữ nghĩa: hoàn thành `MR_SEMANTIC_REVIEW_CHECKLIST.md`.
6. **Mapping.** Chỉ sau khi đã đọc control của đúng phiên bản scanner (Trivy: `~/.cache/trivy/policy/content/policies/kubernetes/policies/*.rego`,
   metadata `custom.id` và `input.selector.subtypes`; Kubescape: `~/.kubescape/c-XXXX.json`, `rules[].match`): thêm vào
   `config/policy-mapping.yaml` (controls + kinds + target). Đây là bước duy nhất cần kiến thức về scanner. Seed cho MR
   candidate đặt trong `seeds/candidate/<tên>/` để không đổi baseline; `mr validate` đã gồm thư mục này.
7. **Chạy thật.** `k8s-mr-lab run --scanner trivy --seeds seeds/synthetic --out runs/x --mr MR-07`, rồi
   `triage`. Đọc `comparisons.csv` chứ không chỉ `results.csv` (cột verdict của `results.csv` chỉ điền khi có VIOLATION). Vi phạm chỉ là *ứng viên* cho tới khi tái hiện và đối chiếu ground truth. Đổi `status` thành
   `mvp_conditional` khi xong; candidate không chạy trong run mặc định.
8. `k8s-mr-lab mr trace --out docs/MR_TRACEABILITY.md` để cập nhật ma trận truy vết.

Số chỗ phải sửa: file transform mới + `catalog.yaml` + (`security_properties.yaml` nếu property mới) + test, và
`policy-mapping.yaml` khi mapping được xác minh.
