# Case study MR-02 `add-unbound-same-name-role`

Mục đích: một hồ sơ mà người chưa đọc mã vẫn phản biện và tái hiện được. Phân biệt rõ năm điều: **MR đúng khi nào**,
**framework kiểm tra được gì**, **scanner quan sát được gì**, **đã thấy violation nào**, **defect nào đã xác nhận**.

Môi trường mọi quan sát bên dưới: Trivy 0.75.0 (checks bundle `sha256:b591e919…`), Kubescape v4.0.15 (artifacts
`8cfb2323…`), local-file mode, chạy lại ngày 2026-11-01. Bằng chứng: `docs/evidence/p0_reverification_2026-11-01/`.

## 1. Phát biểu

*Property* `SP-RBAC-NS-ROLE-RESOLUTION`: một RoleBinding chỉ cấp Role tên N **trong namespace của chính nó**.
*MR-02*: thêm một Role cùng tên N vào một namespace **mới**, không thêm binding nào. Quyền hiệu lực của ServiceAccount
mục tiêu không đổi, nên mọi control đánh giá **quyền của subject đó** (hoặc workload dùng subject đó) phải giữ nguyên verdict
(`relation: equal`).

## 2. Đồ thị object và phép biến đổi

Nguồn `seeds/synthetic/rbac-workload` (gồm 4 object):

```
ServiceAccount lab-a/app  ◀── subject ──  RoleBinding lab-a/app-binding ── roleRef(kind Role, name app-role) ──▶ Role lab-a/app-role
        ▲                                                                                      rules: configmaps get
        └── serviceAccountName ──  Deployment lab-a/web
```

Phép biến đổi `rbac_decoy_role.DecoySameNameRole.transform`: thêm `Role lab-a-decoy/app-role` (profile `secrets_read` hoặc
`wildcard_admin`). Evidence: `diff.json` của case có **đúng một** thay đổi `add_object Role/lab-a-decoy/app-role`; mọi object
khác giữ nguyên từng ký tự (`pair_checks` kiểm điều này).

| Thành phần | Giá trị |
|---|---|
| Target subject | ServiceAccount `lab-a/app` |
| RoleBinding liên quan | `lab-a/app-binding` (không đổi) |
| Role liên quan | `lab-a/app-role` (không đổi) |
| Quan hệ tham chiếu | binding → Role theo `(kind=Role, namespace của binding, name)` |
| Thứ được thêm | một Role ở `lab-a-decoy`, không binding |

## 3. Lập luận tính đúng (proof obligations)

Nguồn ngữ nghĩa đã trích nguyên văn (Kubernetes docs, *Using RBAC Authorization*): "A RoleBinding may reference any Role
in the same namespace" và "Permissions are purely additive (there are no "deny" rules)."

1. Quyền hiệu lực của `lab-a:app` = hợp các rule của mọi Role/ClusterRole được **một binding có subject khớp** tham chiếu.
2. Binding duy nhất có subject đó là `app-binding`, nên Role được cấp là Role `app-role` **trong `lab-a`** (câu trích thứ nhất).
3. Role mới nằm ở `lab-a-decoy`, không binding nào tham chiếu tới nó (validator: số binding không đổi, namespace decoy chỉ chứa Role đó).
   Vì phân giải theo `(namespace của binding)`, nó không thể được chọn làm Role của `app-binding`.
4. Vì quyền chỉ cộng dồn và tập binding không đổi, tập quyền của `lab-a:app` không đổi. ∎

Điều kiện: bundle **đóng** (không có binding nào ngoài bundle cấp thêm cho subject; điều này không ảnh hưởng chứng minh vì
phép biến đổi không thêm binding, nhưng ảnh hưởng việc diễn giải "quyền hiệu lực" tuyệt đối).

### Vì sao `equal` đúng cho từng control được ánh xạ (khẳng định **riêng cho mapping hiện tại**)

| Scanner | Control | Target | Cam kết của control | `equal` đúng nếu |
|---|---|---|---|---|
| Trivy | KSV-0113/0048/0049/0112/0050 | `bound_role` | đánh giá **chính Role đó** (rego chỉ đọc rule của Role được xét) | Role đích không đổi ⇒ verdict không đổi |
| Kubescape | C-0015/0007/0035/0053 | `bound_role` | control RBAC theo subject, Role đích không đổi | scanner ghép binding–Role đúng |
| Kubescape | C-0267/C-0272 | `workload` | "workload dùng SA có role takeover/administrative" | scanner ghép binding–Role **đúng namespace** |
| Kubescape | C-0057 | `workload` | container privileged (không liên quan RBAC) | luôn đúng; đóng vai trò đối chứng |

Dòng C-0267/C-0272 là nơi quan hệ MR thực sự thử scanner: nếu scanner ghép Role theo **tên** mà bỏ qua namespace, nó coi Role
decoy là Role của binding và verdict đổi. Đó chính là hiện tượng đã quan sát (mục 6).

### Trường hợp `equal` KHÔNG còn đúng

* Control **kiểm mọi Role** (ví dụ Trivy KSV-0113 trên chính Role decoy) báo Role decoy là hợp lệ: ngoài scope, không bao giờ so.
* Control đếm hoặc xét hình dạng Role/số object thay vì quyền hiệu lực.
* `roleRef.kind = ClusterRole`: ClusterRole phân giải theo tên, không theo namespace ⇒ MR không áp dụng (CE-4).
* Subject được cấp thêm quyền bằng đường khác (Group `system:serviceaccounts:*`, `system:authenticated`) không bị thay đổi bởi MR, nhưng làm "quyền hiệu lực" lớn hơn bề ngoài; MR vẫn đúng vì chúng không đổi giữa hai phía.
* Bundle không đóng (live cluster): ngoài phạm vi chế độ local-file.

## 4. Positive examples (có test)

`tests/unit/test_mr02_case_study.py::test_positive_examples_every_profile_gives_a_valid_pair`, trên ba seed:

| Seed | RoleBinding→Role | Số params (2 profile) | Kết quả |
|---|---|---|---|
| `rbac-workload` | `app-binding`→`app-role` | 2 | `VALID_PAIR` |
| `rbac-secrets-reader` | `reader-binding`→`reader-role` | 2 | `VALID_PAIR` |
| `K1-role-namespace` (lịch sử) | như `rbac-workload` | 2 | `VALID_PAIR` |

## 5. Counterexamples (có test; nói rõ phần máy chứng minh được)

| ID | Tình huống | Kết quả | Test | Máy chứng minh? |
|---|---|---|---|---|
| CE-1 | decoy đặt trong namespace **đã có** (`lab-a`) | `INVALID_PAIR` | `test_ce1_...` | Có (validator) |
| CE-2 | follow-up sửa luôn RoleBinding (đổi subject) | `INVALID_PAIR`, `diff_is_not_exactly_one_added_object` | `test_ce2_...` | Có |
| CE-3 | namespace decoy chứa thêm một object khác | `INVALID_PAIR` | `test_ce3_...` | Có |
| CE-4 | RoleBinding trỏ ClusterRole | không áp dụng: `no_rolebinding_to_local_role_with_sa_subject` | `test_ce4_...` | Có (precondition) |
| CE-5 | thiếu object ServiceAccount của subject | không áp dụng: `no_target_serviceaccount_object` | `test_ce5_...` | Có |
| CE-6 | scanner báo finding hợp lệ trên **chính Role decoy** | không so; scope không chứa decoy; một FAIL trên decoy không tạo VIOLATION | `test_ce6_...` (hai test) | Có (scope); **ngữ nghĩa** của "scanner có quyền báo" cần con người |
| CE-7 | control không thật sự đánh giá quyền hiệu lực | không tự động phát hiện được | (none) | **Không**: cần đọc rule (checklist mục 3) |

CE-7 là giới hạn trung thực của cổng cấu trúc: mapping control→target do con người xác minh.

## 6. Quan sát thật từ scanner (đã chạy lại 2026-11-01)

MR-02 trên 7 seed: 1 `INVALID_SOURCE`, 2 `SKIP` (không có binding), 4 áp dụng được × 2 profile = 8 cặp mỗi scanner.

| Scanner | PASS | VIOLATION | SKIP | So sánh control×resource (ok / violation) |
|---|---|---|---|---|
| Trivy 0.75.0 | 8 | 0 | 2 | 40 / 0 |
| Kubescape v4.0.15 | 3 | **5** | 2 | 43 / **7** (C-0267: 4, C-0272: 3) |

Kubescape: 5 VIOLATION là **3 cặp input khác nhau** (seed `K1-role-namespace` trùng nội dung `rbac-workload`):
`rbac-workload`/`K1` × {`secrets_read`, `wildcard_admin`} và `rbac-secrets-reader` × `wildcard_admin`. Mẫu:

```
MR-02__rbac-workload__66de14dad8    (profile wildcard_admin)
  diff: add_object Role/lab-a-decoy/app-role         (đúng một thay đổi; VALID_PAIR)
  C-0267 Deployment/lab-a/web   PASS -> FAIL   violation  [verdict tường minh]
  C-0272 Deployment/lab-a/web   PASS -> FAIL   violation  [verdict tường minh]
  C-0057, C-0015, C-0007, C-0035, C-0053 giữ nguyên      (đối chứng: không phải mọi control đổi)
```

Trivy không có violation. Quan sát phụ về CE-6 trong evidence thật: follow-up của Trivy **có** FAIL trên chính Role decoy
(`KSV-0044`/`KSV-0112` ở profile `wildcard_admin`, `KSV-0113` ở `secrets_read`), và MR-02 không so các key đó (`comparisons`
không chứa resource `lab-a-decoy`), đúng thiết kế.

Chạy `k8s-mr-lab mr explain MR-02 --case <thư mục case>` để xem lại từ evidence; xem hướng dẫn từng bước ở mục 7.

## 7. Walkthrough: một case thật, từng bước

Case `MR-02__rbac-workload__66de14dad8` (Kubescape). Mọi đường dẫn tương đối từ `k8s-mr-lab/`.
Thư mục case: `docs/evidence/p0_reverification_2026-11-01/kubescape/cases/MR-02__rbac-workload__66de14dad8/`.

| # | Bước | Mã | Input → Output | Vì sao | Có thể lỗi |
|---|---|---|---|---|---|
| 1 | Source YAML | `bundles.load_bundle` | `seeds/synthetic/rbac-workload/bundle.yaml` → `ConfigBundle` (4 object) | nạp strict | YAML sai |
| 2 | Chọn MR, tham số | `registry.active_mrs`; `DecoySameNameRole.generate_parameters` | → `{rolebinding: app-binding, namespace: lab-a, role: app-role, decoy_namespace: lab-a-decoy, profile: wildcard_admin}` (`trace.json`) | một case mỗi (binding, profile) | không có binding → SKIP |
| 3 | Precondition | `DecoySameNameRole.applicable` | → `(True, "")` | cần RoleBinding→Role cục bộ + SA có thật | CE-4/CE-5 |
| 4 | Biến đổi | `DecoySameNameRole.transform` | → follow-up thêm Role decoy (`followup/bundle.yaml`) | tạo C₂ không sửa C₁ | sửa nhầm source |
| 5 | Kiểm cặp | `DecoySameNameRole.validate_pair` + `validation.diff_bundles` | → `VALID_PAIR`; `diff.json` 1 phần tử | chỉ quét cặp hợp lệ | CE-1..CE-3 |
| 6 | Scope | `checker.static_keys` + `mr.targets` + `policy-mapping.yaml` | → 7 key `(control, resource)` | chỉ so key được cho phép | scope lẫn decoy (CE-6) |
| 7 | Quét nguồn | `Scanner.execute` (kubescape) | → `scanner-source.json`, `invocation-source.json` | cùng binary/policy | SCAN_ERROR |
| 8 | Quét follow-up | `Scanner.execute` | → `scanner-followup.json` | | ENVIRONMENT_MISMATCH nếu khác pin |
| 9 | Chuẩn hóa | `normalize/kubescape.normalize` | → `normalized-source.json`, `normalized-followup.json` | verdict theo `(control, resource)`; `resourceID` RBAC gộp (SA, Role, RoleBinding) | resource không nhận diện được bị bỏ qua + ghi chú |
| 10 | So sánh | `checker.check` (`RELATIONS["equal"]`) | → 5 ok, 2 violation (`assessment.json`) | quan hệ MR là oracle | verdict thiếu → inconclusive |
| 11 | Assessment | `Runner._finish` | → `VIOLATION`, `provenance.json` (version, policy digest, mapping digest, sha256) | tái lập | |
| 12 | Triage | `triage.triage_run` | → `CANDIDATE_REPRODUCED`, `family=kubescape:MR-02:PASS->FAIL`, liên kết `kubescape#2579` | chạy lại, gom họ | **không bao giờ** CONFIRMED |

Các giá trị trong bảng đọc trực tiếp từ các tệp nêu tên, không phải ví dụ giả.

## 8. Kết luận có phân biệt

* **MR-02 hợp lệ về ngữ nghĩa** với `relation: equal` cho các control đã ghi ở mục 3, trong giả định *closed bundle*,
  *RoleBinding→Role cục bộ*, *subject có object trong bundle*. Cơ sở: hai câu trích đã xác minh + lập luận mục 3.
  Lập luận này do tác giả viết (`author_reviewed`); **chưa có review độc lập**.
* **Framework kiểm tra được:** precondition (CE-4/5), cặp hợp lệ (CE-1/2/3), scope không chứa decoy (CE-6), tính xác định và
  không sửa source (`mr validate`). **Không** kiểm tra được CE-7 (control có thật sự đánh giá quyền hiệu lực hay không).
* **Scanner quan sát:** Trivy 0 violation trên 8 case; Kubescape 5 violation (3 cặp input) ở C-0267/C-0272, mọi lần có verdict tường minh.
* **Violation đã thấy:** các PASS→FAIL của C-0267/C-0272 khi thêm Role decoy không bind. 5 dòng ≠ 5 lỗi.
* **Defect đã xác nhận:** **0**. Trạng thái `READY_FOR_HUMAN_ADJUDICATION`. Rego đã pin ghép `roleRef.name` với
  `role.metadata.name` trên mọi Role mà không so namespace (xem `docs/DEFECT_TRIAGE_RESULTS.md`), phù hợp giả thuyết, nhưng
  chưa có adjudication độc lập, chưa thử phiên bản mới hơn (v4.0.16/v4.0.17), và quan hệ với `kubescape#2579` chưa rõ
  (cùng lớp lỗi, chưa chứng minh cùng nguyên nhân).
* **Nghi vấn chưa giải quyết:** (a) control nào thực sự đi qua aggregator của issue #2579; (b) MR-02 chỉ thử profile secrets/wildcard,
  chưa thử Role rỗng hay ClusterRole decoy; (c) K1 là họ lỗi dẫn tới MR-02 nên **không** thể dùng làm bằng chứng độc lập cho MR-02.

## 9. Tái hiện

```bash
# trong môi trường có Trivy 0.75.0 + Kubescape v4.0.15 đã pin (xem docs/SCANNER_VERSIONS.md)
k8s-mr-lab versions
k8s-mr-lab run --scanner kubescape --seeds seeds/synthetic seeds/historical --mr MR-02 --out out/ks-mr02
k8s-mr-lab mr explain MR-02 --case out/ks-mr02/cases/MR-02__rbac-workload__66de14dad8
k8s-mr-lab triage --run out/ks-mr02 --minimize
```

Không cần scanner để kiểm phần cấu trúc: `pytest tests/unit/test_mr02_case_study.py tests/unit/test_mrs.py -q`.
