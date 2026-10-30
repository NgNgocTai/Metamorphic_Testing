# Hướng dẫn tự kiểm tra K1 và N2 (kèm kết quả Claude đã đọc trước)

Mục đích: bạn tự làm lại các bước dưới đây để rồi tự kết luận `CONFIRMED` hay không. Cột "Claude đã thấy" là kết quả tôi đọc ở lần chạy ngày 29/10/2026;
nó **không phải kết luận của bạn**. Mọi lệnh chạy trong Ubuntu (WSL), thư mục `k8s-mr-lab`:

```bash
cd /mnt/d/Code/KLTN/Metarmophic_testing/k8s-mr-lab
ls runs/kubescape/reproducers runs/trivy/reproducers      # mỗi thư mục con là một gói tự chứa
```

## A. Kubescape v4.0.15 — K1 (MR-02)

Ca chính: `runs/kubescape/reproducers/*rbac-workload__e89cd9e383` (Deployment `lab-a/web`, decoy quyền secrets → `C-0267`) và
`*rbac-workload__66de14dad8` (decoy wildcard → cả `C-0267` và `C-0272`). Ngoài ra có `*rbac-secrets-reader*` (Pod, wildcard → `C-0272`).
Cả ba đã chạy lại và cho đúng `passed → failed`.

| # | Bạn làm | Claude đã thấy |
|---|---|---|
| 1 | `bash <gói>/reproduce.sh` | In ra verdict `source … passed` rồi `followup … failed` cho control bị vi phạm |
| 2 | Đọc `<gói>/transformation.diff` | Chỉ **thêm** một Role `app-role` ở namespace `lab-a-decoy` (wildcard hoặc secrets); không đổi dòng nào của object cũ, không thêm binding |
| 3 | Tự hỏi: Role ở `lab-a-decoy` có thể cấp quyền cho ServiceAccount `lab-a/app` không? | Không: RoleBinding ở `lab-a` chỉ phân giải `roleRef` Role trong `lab-a` (kubernetes.io/docs/reference/access-authn-authz/rbac). Nếu bạn không đồng ý ở bước này thì MR-02 sai, không phải scanner |
| 4 | Mở `<gói>/scanner-followup.json`, tìm control `C-0267` của `Deployment/web` | `status: failed`; trong `relatedResourcesIDs` có `.../lab-a-decoy/Role/app-role`, tức Kubescape tự dùng Role decoy làm căn cứ |
| 5 | Mở `~/.kubescape/c-0267.json` và `c-0272.json`, xem phần `rule` | `C-0267` L20–27 và `C-0272` L21–27: `role := input[_]` rồi `rolebinding.roleRef.name == role.metadata.name`; **không** so namespace của Role. `C-0272` còn không so `roleRef.kind` |
| 6 | `python scripts/triage_probe.py` rồi đọc `docs/evidence/k1_kubescape_ablation.json` | Decoy khác tên → PASS; decoy tên giống nhưng quyền vô hại → PASS; Role local cấp secrets thật → FAIL (đúng). Nên kích hoạt do **trùng tên + quyền của decoy** |

**Câu bạn cần tự trả lời:** có phải rule `C-0267/C-0272` ghép Role theo tên bỏ qua namespace là *lỗi* (false positive) hay là chủ ý thiết kế? Rồi tra xem upstream đã báo/sửa chưa
(issue kubescape#2579 là lớp lỗi tương tự nhưng ở hàm khác; chưa xác minh bản sửa của nó) và thử Kubescape 4.0.16 trong `D:\Code\KLTN\Tools`.

## B. Trivy 0.75.0 — N2 (MR-05)

Gói: `runs/trivy/reproducers/*MR-05*`.

| # | Bạn làm | Claude đã thấy |
|---|---|---|
| 1 | `bash <gói>/reproduce.sh` | `KSV-0113 FAIL` ở cả `source` lẫn `followup` cho Role `reader-role` |
| 2 | Đọc `transformation.diff` | Đúng một thay đổi: `apiGroups: ''` → `apps` (rule duy nhất của Role, resource `secrets`) |
| 3 | Tự hỏi: Role chỉ cấp "secrets" trong group `apps` có cấp quyền đọc Secrets không? | Không: Secrets thuộc core group `""`. Kubescape `C-0015` cùng cặp: FAIL → PASS (đúng) |
| 4 | `cat ~/.cache/trivy/policy/content/policies/kubernetes/policies/manage_namespace_secrets.rego` | L34–39: chỉ so `resources[...] == "secrets"` và verb; **không có chữ `apiGroups`** trong cả tệp |
| 5 | Đọc `docs/evidence/n2_trivy_ablation.json` | `apps` + secrets → FAIL; group không tồn tại + secrets → FAIL; `apps` + deployments → PASS: check phân biệt resource nhưng không phân biệt API group |

**Câu bạn cần tự trả lời:** `KSV-0113` nhằm đánh giá quyền hiệu lực trên Secrets (khi đó đây là false positive mức thấp) hay chỉ cảnh báo mọi rule nhắc tới `secrets`? Đối chiếu mô tả check trên trang AVD của Trivy, tìm issue upstream, thử Trivy 0.76.1.

## C. Điều Claude phát hiện khi đọc lại (cần biết trước khi bạn kết luận)

1. **`PASS` của Trivy yếu hơn tôi từng mô tả.** Probe mới: một file chỉ có Role chứa `secrets` → `KSV-0113` FAIL=1, PASS=0. Thêm *bất kỳ* object khác (ServiceAccount, RoleBinding hay Pod) → xuất hiện PASS=1 **dù Role vẫn FAIL**.
   Vậy PASS của Trivy là entry cấp file, không phải bằng chứng một resource nào đã được đánh giá. Với Trivy, các kết quả MR "PASS" thực chất chỉ nói *tập FAIL không đổi*; kết luận N2 không bị ảnh hưởng vì nó dựa trên **FAIL gắn resource ở cả hai phía**. Tài liệu và code đã được chỉnh lại câu chữ cho khớp.
2. **Gói reproducer đại diện cũ chỉ có một ca/họ.** Ca đầu tiên của họ Kubescape là `rbac-secrets-reader` (Pod, `C-0272`), không phải ca K1 Deployment `web` mà hồ sơ mô tả. Tôi đã sửa để mỗi cặp input duy nhất có một gói riêng (xem thư mục `reproducers/`).
3. **Điểm trình bày:** K1/N2 đều được chọn trước để viết MR (guided). Việc chúng tái hiện được không phải là tỉ lệ phát hiện lỗi.

## D. Khi xong
Ghi kết luận của bạn (CONFIRMED / không phải lỗi / cần thêm bằng chứng) vào cuối `docs/DEFECT_TRIAGE_RESULTS.md`; không cần sửa code.
