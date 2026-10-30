# Báo cáo PoC: Metamorphic Testing (MR-first) cho Trivy và Kubescape

Viết cho: giảng viên hướng dẫn — để đánh giá tiến độ và duyệt hướng nghiên cứu tiếp theo.
Ngày chạy thực nghiệm: 29/10/2026. Mọi số liệu lấy từ `runs/summary/REPORT.md` và `docs/evidence/` (scanner thật, không mock).

## 1. Bài toán nghiên cứu

Trivy và Kubescape được dùng để phát hiện misconfiguration, nhưng chính scanner cũng có thể đánh giá sai khi nhiều resource tương tác
(ví dụ ghép `RoleBinding`–`Role`) hoặc khi cùng một quyền được biểu diễn theo cách khác. Khó khăn: không thể viết trước danh sách finding
đúng cho từng cấu hình (test oracle problem). Đề tài **kiểm thử độ đúng của scanner**, không phải tìm cấu hình sai trong một cluster.

Ba câu hỏi nghiên cứu: **RQ1 Applicability** (xây và áp dụng được những MR nào), **RQ2 Effectiveness** (phát hiện được loại lỗi nào, tin cậy ra sao),
**RQ3 Efficiency & Practicality** (chi phí sinh, thực thi, triage). Không có giả thuyết "MR tốt hơn random": bài Web về Metamorphic Testing cũng đánh giá
khả năng áp dụng, phát hiện lỗ hổng, specificity và chi phí chứ không đặt so với random làm điều kiện; so sánh đó nằm ở Future Work.

## 2. Phương pháp MR-first

Một MR là `(Precondition, Transformation, ExpectedRelation, Scope)` và đóng **hai vai trò**: (1) sinh follow-up `C2 = T(C1)` từ cấu hình nguồn `C1`;
(2) làm **oracle quan hệ**: cùng một scanner chạy trên `C1` và `C2`, findings được chuẩn hóa rồi kiểm `R(N(S(C1)), N(S(C2)))`.
Không có Semantic Oracle, SubjectAccessReview hay cluster trong pipeline (có test chặn việc thêm vào nhầm).

Ví dụ MR-02: RoleBinding ở `lab-a` trỏ Role cùng namespace; thêm Role **trùng tên** ở namespace khác, **không bind**. Theo RBAC, quyền của ServiceAccount không đổi,
nên verdict của control đánh giá nó phải bất biến. Cơ sở là quy tắc K8s "RoleBinding chỉ phân giải Role trong namespace của nó", không phải một oracle chạy kèm.

Nguyên tắc trung thực của khung: vắng finding **không** phải PASS; mọi cặp có trạng thái `PASS / VIOLATION / SKIP / INVALID_PAIR / INCONCLUSIVE / SCAN_ERROR /
ENVIRONMENT_MISMATCH`; `VIOLATION` chỉ là alert, chưa là bug.

## 3. Những gì đã triển khai

* Repo `k8s-mr-lab/`: loader YAML chặt (từ chối key trùng), 5 MR (`mrs/catalog.yaml`), validator cấu trúc, adapter gọi **Trivy 0.75.0 và Kubescape v4.0.15 thật** (quét manifest, offline, pin version + digest policy),
  hai normalizer, checker (`equal`/`pass_to_fail`/`fail_to_pass`), runner có provenance, triage (chạy lại, reproducer), report với mẫu số rõ.
* 83 test (unit, golden từ raw JSON thật, integration chạy binary thật) đều pass trên máy chạy thực nghiệm; trên máy không có đúng binary đã pin thì 3 test integration bị skip (chỉ 80 chạy).
* Sau một đợt review độc lập (30/10/2026) đã siết: kết quả `PARTIAL` thay cho `PASS` khi một phần scope không có verdict; MR-05 không áp dụng control cấp subject/workload khi quyền đọc Secrets còn được cấp bằng đường khác;
  validator MR-04 kiểm đúng container; scanner có mã thoát khác 0 hoặc thiếu policy digest bị báo `SCAN_ERROR`. Các thay đổi này không làm đổi số liệu đã báo cáo (xem mục 5).
* Hạn chế PASS của Trivy đã kiểm chứng và xử lý: entry `PASS` không gắn resource; FAIL được gắn bằng ánh xạ dòng, PASS chỉ là suy luận có nhãn `pass_inferred`.

| MR | Biến đổi | Quan hệ | Nhóm OWASP K8s Top 10 (2025) | Căn cứ dẫn xuất |
|---|---|---|---|---|
| MR-01 | đảo/sắp xếp thứ tự key YAML | `equal` | — (không gắn nhóm rủi ro) | ngữ nghĩa YAML: thứ tự key của mapping không đổi object |
| MR-02 | thêm Role trùng tên, không bind, ở namespace mới | `equal` | K02 Overly Permissive Authorization Configurations | Kubernetes RBAC: RoleBinding chỉ tham chiếu Role cùng namespace hoặc ClusterRole |
| MR-03 | tách rule nhiều verbs thành nhiều rule | `equal` | K02 | Kubernetes RBAC: quyền cộng dồn, nhiều rule bằng một rule gộp |
| MR-04 | `privileged: false → true` | `pass_to_fail` | K01 Insecure Workload Configurations | Pod Security Standards: `privileged` bị cấm ở mức Baseline |
| MR-05 | rule `secrets` core group → apiGroup `apps` | `fail_to_pass` | K02 và K03 Secrets Management Failures | Kubernetes API: Secrets thuộc core group `""` |

**MR được viết theo thuộc tính bảo mật Kubernetes, không theo scanner.** Phép biến đổi và quan hệ nằm trong `mrs/catalog.yaml` và `src/k8s_mr_lab/transforms/`, dùng chung cho mọi scanner; phần riêng của từng scanner chỉ là adapter, normalizer và bảng ánh xạ control (`config/policy-mapping.yaml`). Không phải MR nào cũng áp dụng cho mọi scanner: chỉ áp dụng khi scanner có control đánh giá đúng thuộc tính đó. Trivy và Kubescape đóng vai trò giống Jenkins và Joomla trong bài Web: hai hệ thống thật để đánh giá phương pháp, không phải giới hạn của phương pháp.

Căn cứ của MR-04 đã đối chiếu với trang Pod Security Standards: control "Privileged Containers" ở mức Baseline chỉ cho phép `privileged` không khai báo hoặc `false`, áp dụng cho cả `containers`, `initContainers` và `ephemeralContainers` (PoC mới kiểm thử `containers`).

Cột OWASP là **mapping do đề tài tự gán** (OWASP không định nghĩa các MR này); cách làm giống bài Web, nơi tác giả tự gắn mã CWE/OWASP cho từng MR của họ.
Lưu ý: mã nhóm theo **bản 2025** (bản 2022 đánh số khác: RBAC là K03, Secrets là K08).

Miền bao phủ: RBAC (MR-02/03/05) và một phần Pod Security (MR-04); chưa có MR cho ServiceAccount token. Theo OWASP K8s Top 10 2025, PoC mới chạm K01 (một phần), K02 và K03 (một phần qua MR-05).

## 4. Thiết kế thực nghiệm

Bảy thư mục seed (6 hợp lệ, 1 cố ý sai để kiểm `INVALID_SOURCE`), trong đó `K1-role-namespace` là seed lịch sử trùng nội dung với `rbac-workload`. Mỗi cặp chạy trên cả hai scanner
cùng version/mode/policy; nguồn được cache theo hash văn bản. Bằng chứng ở mức **DEV/REG (có định hướng)**: MR-02 và MR-05 được viết sau khi biết lớp lỗi K1/N2.
Ngoài ra có một lượt **chạy độc lập sau khi đóng băng catalog** trên manifest của bên thứ ba (mục 5b). Local-file mode cho cả hai scanner (live-cluster chưa dùng, không cần cho hai ứng viên). Kết quả giống hệt qua nhiều lần chạy lại từ đầu.

## 5. Kết quả thực tế

**Số dòng và khử trùng** (mỗi scanner): 41 dòng kết quả = 15 chưa chạy scanner (14 `SKIP` + 1 `INVALID_SOURCE`) + 26 cặp hợp lệ; 21 cặp **duy nhất** (5 follow-up trùng do seed K1).

| | Trivy 0.75.0 | Kubescape v4.0.15 |
|---|---|---|
| PASS / VIOLATION / INCONCLUSIVE | 25 / 1 / 0 | 20 / 5 / 1 |
| VIOLATION trên cặp duy nhất | 1 | 3 |
| Họ nguyên nhân giả định | 1 | 1 |
| Defect đã xác nhận | 0 | 0 |

Tổng: **6 dòng alert = 4 cặp input duy nhất = 2 họ ứng viên**, 0 confirmed.

> **Hai lưu ý khi đọc số liệu**
> 1. **PASS** nghĩa là *quan hệ MR được thỏa*, không có nghĩa scanner đã xác nhận resource an toàn.
> 2. **Ứng viên lỗi** nghĩa là hiện tượng đã tái hiện được và có bằng chứng kỹ thuật, nhưng *chưa kết luận chính thức* là lỗi scanner.

**RQ1 (Applicability).** (seed, MR) áp dụng được: 16/30 (53%) mỗi scanner. Theo MR: MR-01 6/6 seed, MR-02 4/6, MR-04 4/6, MR-03 1/6, MR-05 1/6 (số follow-up: 11, 8, 5, 1, 1).
Lý do `SKIP`: thiếu RoleBinding cục bộ (2), không có rule ≥ 2 verbs (5), không có Role chỉ-đọc-secrets (5), không có `privileged: false` tường minh (2). Mỗi MR có ≥ 1 counterexample bị validator từ chối (kiểm bằng test).
Phạm vi control: 6 check Trivy và 7 control Kubescape có mapping đã đọc từ metadata rule. `valid_pair_rate` = 26/26 chỉ là thông tin phụ vì cặp sinh từ cấu trúc.

**RQ2 (Effectiveness).** Hai lớp lỗi K1 và N2 được **chọn trước** để viết MR tái hiện, và cả hai đều tái hiện được. Đây là kiểm thử có định hướng, **không phải tỉ lệ phát hiện lỗi**; các case cũ khác (K2, N1, N3, P1) chưa có MR nên chưa thử.
`alert precision` và `specificity` **chưa đo** (chưa adjudication thủ công, chưa có negative case gán nhãn độc lập). Kết quả âm có thật: MR-01 trên seed chỉ có Role không bind cho Kubescape là `INCONCLUSIVE` (không có verdict), không bị tính PASS.

**RQ3 (Efficiency & Practicality).** Từ log của runner: tạo và kiểm tra cấu trúc một cặp: trung vị dưới ~100 ms (tổng ≈ 2,1 s); một lượt gọi scanner trung bình ≈ 1,5 s (Trivy, 26 lượt = 38,6 s) và ≈ 3,7 s (Kubescape, 26 lượt = 96,6 s) ở lần chạy cuối (thời gian dao động nhẹ giữa các lần chạy, số đếm thì không đổi);
26 lần quét được tiết kiệm nhờ cache nguồn; tỉ lệ cặp có kết luận theo quy tắc của framework (PASS+VIOLATION trên cặp đã tới scanner): Trivy 26/26, Kubescape 25/26. Khối lượng triage thủ công: 6 alert → 4 input → 2 họ.
Thời gian người nghiên cứu bỏ ra để triage chưa được ghi nên không báo. Demo ngắn: `scripts/demo_mr02.sh` (~15 s, Kubescape thật); demo phụ `scripts/demo_mr02.sh --scanner trivy --mr MR-05 --out runs/demo_mr05`.

## 5b. Lượt chạy độc lập trên manifest của bên thứ ba (đóng băng catalog)

**Thiết lập (quyết định trước khi chạy):** Kalm-Benchmark (Dynatrace, commit `dac3df5`), do người khác viết, chưa từng dùng để thiết kế hay chỉnh MR (trước đó chỉ đếm xem MR có áp dụng được không, chưa xem kết quả scanner).
Digest của catalog, mapping, config và toàn bộ code MR được ghi vào `runs/heldout/freeze.json` trước khi chạy và **còn nguyên sau khi chạy** (`FREEZE INTACT`).
Chọn 65 file theo quy tắc cố định: bỏ file bắt đầu bằng `_`, lấy mỗi file thứ 4, cộng mọi file mà MR-02/03/05 áp dụng được (8 file). Cả hai scanner thật, cùng phiên bản và policy như trên.

| Mỗi scanner | Trivy 0.75.0 | Kubescape v4.0.15 |
|---|---|---|
| Seed / follow-up sinh ra (đều khác nhau về nội dung) | 65 / 141 | 65 / 141 |
| PASS / VIOLATION / INCONCLUSIVE | 131 / 3 / 5 | 110 / 0 / 29 |
| Tỉ lệ cặp có kết luận (PASS+VIOLATION) | 134/139 = 96% | 110/139 = 79% |
| Phép so sánh có kết luận dựa vào PASS suy luận | 247/339 = 73% | 0/693 |
| Thời gian quét trung bình mỗi lượt gọi / tổng | ≈ 1,2 s / 233 s | ≈ 4,2 s / 840 s |

**Đọc kết quả thế nào:**
* **Không quan sát MR violation nào ở MR-01 (95 cặp) và MR-04 (33 cặp)** trong tập chạy này, ở cả hai scanner. Đây là bằng chứng ban đầu rằng các quan hệ ổn định trên dữ liệu bên thứ ba và không bị tinh chỉnh cho riêng seed của đề tài, nhưng **chưa đủ để kết luận tỉ lệ cảnh báo giả bằng 0**: không có violation không đồng nghĩa đã đo specificity.
* **Mẫu số:** 141 follow-up sinh ra = 139 cặp có kết quả (PASS, VIOLATION hoặc INCONCLUSIVE) + **2 cặp SKIP sau khi quét** (`no_comparable_keys`: MR-01 trên `rbac-016-serviceaccount-without-binding` và `rbac-027-1-role-binds-to-anonymous-unauthenticated`, không có control đã ánh xạ hay failure nào để so). Hai cặp này giống nhau ở cả hai scanner.
* **N2 của Trivy tái hiện trên seed độc lập:** 3 violation MR-05 trên `rbac-002-1/2/3` của Kalm (Role chỉ cấp `secrets` ở core group; đổi sang `apps` thì `KSV-0113` vẫn FAIL). Đây là ba biến thể của cùng một kịch bản, nên vẫn **một họ**, không phải ba lỗi. Nó cho thấy N2 không phải sản phẩm của seed tự viết, nhưng MR-05 vốn được viết sau khi biết N2.
* **K1 của Kubescape không xuất hiện ở đây.** K1 cần ServiceAccount + RoleBinding + workload dùng SA đó; manifest Kalm gần như không có tổ hợp này (MR-02 chỉ áp dụng 3 file, đều cho PASS). Đây là hạn chế về seed, không phải bằng chứng rằng lỗi hiếm.
* **Áp dụng:** 105/320 = 33% (seed, MR). Số seed áp dụng được trên 65: MR-01 62 (95 cặp), MR-04 33, MR-02 3, MR-03 2, MR-05 3. MR RBAC cần seed có nhiều resource liên kết, mà benchmark đơn-lỗi không cung cấp.
* **INCONCLUSIVE (Trivy 5, Kubescape 29) là trung thực, không phải lỗi:** Trivy: 5 cặp có FAIL không có số dòng (`StartLine` trống) nên không gắn được resource, framework từ chối kết luận.
  Kubescape: cả 29 đều là file RBAC chỉ có một Role hoặc ClusterRole đứng riêng, không có binding hay ServiceAccount (24 ở MR-01, 5 ở MR-03/MR-05). Các control RBAC của Kubescape đánh giá theo subject nên không phát verdict nào cho Role không được bind, framework không có gì để so và báo INCONCLUSIVE thay vì PASS. Nút thắt khi mở rộng seed là **seed có đủ liên kết RBAC** và **độ phủ control của mapping**, không phải thiết kế MR.
* **Chi phí:** 205 lượt quét mỗi scanner, 77 lượt tiết kiệm nhờ cache; tổng sinh cặp ≈ 14 s; 0 `SCAN_ERROR`.

**Giới hạn:** một benchmark duy nhất; 65/238 file **không phải mẫu ngẫu nhiên** (mỗi file thứ 4 cộng ưu tiên toàn bộ file mà MR RBAC áp dụng được, nên thành phần RBAC được tuyển chọn); chưa có adjudication thủ công; 73% số so sánh có kết luận của Trivy dựa vào PASS suy luận. Không dùng kết quả này làm tỉ lệ phát hiện lỗi hay tỉ lệ cảnh báo giả.

**Tái lập:** commit Kalm `dac3df5`, hash sha256 của từng file đã chọn nằm trong `runs/heldout/selection.json`, digest đóng băng trong `runs/heldout/freeze.json`. Gói bằng chứng tối thiểu (0,5 MB, không gồm 70 MB artifact tái sinh được): `runs/evidence-pack.zip` do `python scripts/make_evidence_pack.py` tạo, kèm `MANIFEST.sha256.json`. Raw report trong gói có đường dẫn cục bộ (tên người dùng trong `/home/...`), không có thông tin xác thực; xem lại trước khi gửi ra ngoài.

## 6. Phân tích hai ứng viên lỗi

Chi tiết, ablation và các khả năng đã loại trừ: `docs/DEFECT_TRIAGE_RESULTS.md` (trạng thái `READY_FOR_HUMAN_ADJUDICATION`).

1. **Kubescape, MR-02 (lớp K1).** Role decoy không bind làm `C-0267` (và `C-0272` với profile wildcard) của workload đổi `passed → failed`. Rule rego ghép Role–RoleBinding theo tên và bỏ qua namespace;
   chính raw JSON của Kubescape liệt kê Role decoy trong `relatedResourcesIDs` của alert. Ablation: Role decoy khác tên hoặc quyền vô hại → PASS; Role local cấp secrets thật → FAIL (đúng). Cùng lớp lỗi với issue kubescape#2579
   nhưng **không chứng minh cùng nguyên nhân gốc**: các control dùng aggregator (`C-0015` …) không bị ảnh hưởng trên v4.0.15. Chưa xác minh bản sửa của #2579.
2. **Trivy, MR-05 (lớp N2).** `KSV-0113` vẫn FAIL khi `apiGroups: ["apps"]` hoặc một group không tồn tại, nhưng PASS khi resource không phải secrets; rego không chứa `apiGroups`. Đây là false positive mức thấp nếu coi
   check nhằm phát hiện quyền thật. Bằng chứng dựa trên FAIL có gắn resource, không dựa trên PASS suy luận. Kubescape xử lý đúng cùng cặp.

Cả hai là lớp lỗi đã được biết trước (guided), không gọi là phát hiện mới.

## 7. Những giới hạn

* Phần DEV/REG là có định hướng và số seed nhỏ (có seed trùng nội dung, đã khử trùng). Lượt độc lập (mục 5b) chỉ là một mẫu 65 file của một benchmark duy nhất, các MR RBAC hầu như không áp dụng được ở đó, và chưa có adjudication thủ công.
* Chưa có adjudication thủ công: 0 defect confirmed; không báo alert precision/specificity.
* MR bất biến bỏ sót lỗi sai nhất quán; Trivy PASS là suy luận (không dùng làm bằng chứng chính): 100 trên 256 phép so sánh có kết luận của Trivy (khoảng 39%) dựa vào PASS suy luận, nên với Trivy phần lớn kết quả "PASS" nghĩa là "tập FAIL không đổi"; Kubescape thì 0/382 vì verdict của nó tường minh.
* Kubescape báo kết quả RBAC theo từng bộ ba (subject, Role, RoleBinding); normalizer gán verdict đó cho từng thành viên và lấy trạng thái xấu nhất khi một đối tượng xuất hiện nhiều lần. Đã kiểm bằng ca đối kháng thật (một SA có Role vô hại và Role Secrets, SA thứ hai chỉ dùng Role vô hại): verdict của từng Role và từng SA đúng, không bị lẫn. Chưa kiểm các cấu hình phức tạp hơn (ClusterRole, nhiều subject trong một binding, group).
* Validator nguồn chỉ kiểm cấu trúc (khóa trùng, định danh, RoleBinding tham chiếu Role cùng namespace), chưa kiểm schema Kubernetes; kết luận chỉ hợp lệ ở chế độ quét manifest cục bộ.
* Gom họ lỗi (`family`) là heuristic theo scanner + MR + kiểu đổi verdict; việc tách/gộp theo nguyên nhân gốc thật là của người adjudicate.
* Mapping control→MR mới 6 check Trivy + 7 control Kubescape; chưa bao phủ token (không có MR), init container, securityContext override.
* Chỉ một phiên bản mỗi scanner, chỉ chế độ quét manifest; chưa rõ lỗi còn ở bản mới hơn.
* Chưa xác minh trạng thái sửa lỗi của issue #2579 và chưa tìm issue upstream cho `KSV-0113`.

## 8. Kết luận và kế hoạch nghiên cứu tiếp theo

**Kết luận.** Framework đã triển khai năm Metamorphic Relations để kiểm thử Trivy và Kubescape. Thực nghiệm trên hai scanner thật phát hiện sáu cảnh báo vi phạm MR,
tương ứng với bốn cặp đầu vào khác nhau, được nhóm thành hai họ ứng viên lỗi. Các hiện tượng này tái hiện được và có bằng chứng từ mã kiểm tra bảo mật của scanner.
Tuy nhiên, đây là những trường hợp kiểm thử có định hướng, chưa phải phát hiện lỗi mới. Kết quả PoC bước đầu cho thấy phương pháp Metamorphic Testing có thể được tự động hóa và áp dụng để phát hiện những hành vi không nhất quán trong Trivy và Kubescape;
hai họ ứng viên lỗi đã được tái hiện và phân tích nguyên nhân. Trong giai đoạn tiếp theo, nghiên cứu sẽ mở rộng phạm vi MR và đánh giá phương pháp trên nhiều cấu hình Kubernetes hơn.

| Ưu tiên | Việc | Mục đích |
|---|---|---|
| 1 | Người nghiên cứu adjudicate hai ứng viên; tra issue/PR upstream; thử Kubescape 4.0.16 và Trivy 0.76.1 | Chuyển candidate → confirmed/không; biết lỗi còn ở bản mới không |
| 2 | Mở rộng lượt độc lập: thêm seed có đủ ServiceAccount–Role–RoleBinding–workload (Kalm hầu như không có), chạy nốt phần chưa chọn của Kalm (173 file) cho các MR mới | RQ2 ngoài tập phát triển; báo cả khi không có violation |
| 3 | Hệ thống hóa RQ1 theo OWASP K8s Top 10 2025: duyệt K01–K10, với mỗi nhóm thử dẫn xuất MR từ tài liệu Kubernetes và ghi lý do khi không viết được (như bài Web làm với CWE); trước mắt thêm MR cho ServiceAccount token và Pod Security (securityContext override, init container) có precondition + counterexample | Chứng minh phương pháp không chỉ RBAC và có căn cứ chọn MR (RQ1) |
| 4 | Ghi thời gian triage thủ công; mở rộng mapping control | RQ3 đầy đủ hơn |
| Sau | Live-cluster scanning; so sánh random/schema-aware (Phụ lục E.6); Semantic Oracle độc lập | Future Work, không bắt buộc cho RQ1–RQ3 |
