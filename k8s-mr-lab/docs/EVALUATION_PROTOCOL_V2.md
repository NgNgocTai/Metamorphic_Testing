# Giao thức đánh giá V2

Phân biệt **đã thực thi** (có evidence trong repo) và **đề xuất** (chưa làm) ở từng mục. Mọi con số dưới nhãn "đã thực thi" đọc từ
`docs/evidence/`; không có con số nào được ước lượng.

## 1. Ba câu hỏi nghiên cứu và đo gì

| RQ | Câu hỏi | Chỉ số (mẫu số bắt buộc ghi kèm) | Không được suy ra |
|---|---|---|---|
| RQ1 Applicability | MR áp dụng được trên những property, resource, control, seed nào? | `applicable_seed×MR / eligible`, follow-up sinh ra, `VALID_PAIR`, cặp so sánh được, tỉ lệ `SKIP / INVALID_* / INCONCLUSIVE / PARTIAL`, coverage property/control (`COVERAGE_DEFINITIONS` ở WP2) | số MR nhiều ⇒ chất lượng |
| RQ2 Effectiveness | Có phát hiện bất nhất/lỗi scanner không? | raw violation, cặp input duy nhất, họ ứng viên, tái hiện, **confirmed**; **sensitivity trên known-defect đủ điều kiện (k/n)**; **mutation score** (bảng riêng); báo động giả do MR/framework | violation = bug; guided = blind; kết quả KALM = tỉ lệ phát hiện |
| RQ3 Efficiency | Chi phí và tính thực dụng? | thời gian sinh/kiểm cặp, số lần quét, thời gian quét, cache hit, khối lượng triage, dung lượng evidence | "tối ưu" khi chưa có baseline cùng ngân sách |

Số liệu RQ3 đo được hiện có: mỗi run đầy đủ 26 lần gọi scanner cho 41 dòng kết quả; `results.csv` có `gen_ms`, `scan_ms`, `cache_hits`
(`report.py`). Chưa tổng hợp thành bảng chi phí chuẩn: **đề xuất**.

## 2. Thu thập source input có hệ thống (đề xuất; hiện chỉ có 8 seed)

MST-wi lấy source input bằng crawler (duyệt đồ thị trạng thái, DFS gốc→lá) cộng test script viết tay [bài báo §6]. Tương ứng cho K8s,
**chưa thực thi** ngoài hai nguồn đầu:

| Nguồn | Trạng thái | Vai trò | Kiểm soát |
|---|---|---|---|
| Seed tổng hợp viết tay theo property | **có** (6) | sâu, có chủ đích (như test script của họ) | ghi property mà seed phục vụ |
| Seed lịch sử (K1) | **có** (1) | hồi quy | phân vùng DEV/REGRESSION |
| Manifest benchmark KALM | **có** 65/238 đã chạy (`runs/heldout`), dữ liệu đã *nhìn* ⇒ không còn "mù" cho MR viết sau | rộng, bên thứ ba | không dùng làm held-out cho MR mới |
| Manifest từ benchmark ISSTA, kho cấu hình thật (Helm chart render, kustomize) | **chưa** | đa dạng thực tế | thu thập script + hash; giấy phép |
| **Bộ ghép đồ thị** (linked bundles) từ nhiều manifest | **chưa** | MR cần Binding+Role+SA+workload; manifest rời không đủ ngữ nghĩa | báo `COMPLETE_FOR_MR_SCOPE / PARTIAL_BUNDLE / AMBIGUOUS_BINDING`; không ghép theo tên |

**Chọn và đa dạng hóa seed (đề xuất):** mỗi seed gắn vector đặc trưng (kind có mặt, kiểu subject, loại roleRef, số namespace, có workload
dùng SA, có wildcard, số rule/verb), chọn tập seed phủ tối đa các giá trị vector theo MR (greedy set cover) thay vì "mỗi mẫu thứ 4".
**Coverage seed** = `|{giá trị đặc trưng phủ bởi tập seed}| / |{giá trị đặc trưng đã định nghĩa}|` và, theo MR, số seed áp dụng được.
Không tính coverage trên tập đặc trưng chọn sau khi biết kết quả.

**Bằng chứng seed là điểm yếu (đã thực thi):** thí nghiệm mutant ở §5 cho thấy một lỗi chèn *sống sót* trong cả 46 case; một phần
nguyên nhân là **không seed nào có hai SA cùng tên khác namespace**, tức là seed chưa đủ chứ không chỉ MR chưa đủ.

## 3. Phân vùng dữ liệu (chống rò rỉ)

| Phân vùng | Nội dung hiện có | Được sửa MR theo kết quả? | Dùng cho tỉ lệ độc lập? |
|---|---|---|---|
| DEV | 6 seed tổng hợp, `seeds/candidate`, K1/N2 | có | **không** |
| REGRESSION | baseline PoC (41 + 41 dòng; 256 + 386 so sánh), snapshot hành vi MR-01..05 | không (đóng băng) | không |
| KALM-2026 | 65 manifest đã chạy cho catalog PoC | không | không cho MR viết sau khi xem |
| EVAL-FUTURE | **chưa có** | không | có, nếu đóng băng trước khi xem output |
| KNOWN_DEFECT_EVAL | **chưa có mục đủ điều kiện** | không | có (mẫu số định nghĩa trước) |

Quy tắc: sửa MR sau khi xem kết quả ⇒ dữ liệu đó thành DEV; kiểm tra bản sửa trên phân vùng mới. MR-06, MR-07 hiện chỉ có bằng chứng DEV.

## 4. Baseline so sánh (đề xuất, có giới hạn)

| Baseline | So được gì | Không so được |
|---|---|---|
| Source-only (quét C₁, không follow-up) | số control×resource có verdict, độ ổn định giữa hai lần quét | khả năng phát hiện bất nhất (không có oracle) |
| Quét lặp cùng input (kiểm xác định) | nhiễu của scanner: nền cho "VIOLATION do không xác định" | |
| Biến đổi ngẫu nhiên hợp lệ cùng ngân sách (thêm object ngẫu nhiên không bind) | số violation / lượt quét so với MR-guided | chỉ có nghĩa khi có ground truth để chấm violation nào đúng |

Không tuyên bố "MR-guided tốt hơn ngẫu nhiên" khi chưa có ground truth. Static và live-cluster **không trộn** (coverage khác nhau).

## 5. Đánh giá bằng đột biến / chèn lỗi (mutation / fault injection)

Phân biệt ba loại và không cộng chung vào một phần trăm:

| Loại | Định nghĩa | Ví dụ |
|---|---|---|
| Injected fault (mutant) | sửa mã/policy của *bản sao cô lập* của scanner | bỏ so sánh namespace của subject trong `C-0267` |
| Fix-validation (historical defect đã vá giả định) | vá lỗi đã quan sát, kiểm lỗi hết | thêm so sánh namespace vào join Role–RoleBinding của `C-0267` |
| Newly discovered | phát hiện trên scanner nguyên bản | K1/N2, MR-07 FAIL→PASS (đều **candidate**) |

**Thiết kế (đã cài đặt công cụ: `scripts/fault_variant_kubescape.py`):** sao chép `~/.kubescape` sang thư mục riêng, sửa rego của *một*
control, chạy runner bằng `--config` trỏ `artifacts_dir` vào bản sao. Policy digest khác ⇒ runner tách track (từ chối so sánh với digest cũ).
Bản gốc không bị sửa. Trivy: tương tự được (check là rego), **chưa làm**.

**Quy tắc kết luận:** một mutant bị *kill* nếu bộ MR báo VIOLATION (hoặc kết quả khác) mà scanner gốc không báo trên cùng case. Phải
(i) khai báo *dự đoán trước khi chạy*, (ii) so từng case và từng khóa verdict với baseline đã ghim, (iii) xét mutant tương đương
(mutant không đổi hành vi trên mọi input hợp lệ không thể bị kill), (iv) ghi seed có kích hoạt được mutant không.

**Kết quả đã thực thi (2026-11-01, Kubescape v4.0.15; `docs/evidence/fault_variants_2026-11-01/`):**

| Thí nghiệm | Dự đoán nêu trước | Quan sát |
|---|---|---|
| Fix-validation `namespace-fix` trên `C-0267`, chạy MR-02 | 4 violation của C-0267 biến mất; 3 của C-0272 (không vá) còn; chỉ khóa của C-0267 đổi | **đúng**: C-0267 4 → 0; C-0272 3 → 3; 4/50 khóa đổi, toàn bộ ở C-0267; policy digest `777e0574…` ≠ `8cfb2323…` |
| Mutant `drop-subject-ns` (bỏ so sánh namespace của subject trong C-0267), chạy MR-01..05 + MR-07 | mutant **sống sót** (không MR nào đụng namespace của subject) | **đúng**: 46/46 case cùng kết quả MR, 404/404 khóa verdict giống scanner gốc |

Diễn giải: (a) với fix-validation, MR-02 *phân biệt đúng control bị lỗi*, nhưng đây là bản vá do tác giả viết, không phải bản vá upstream, nên
nó chỉ cho thấy "MR nhạy với đúng điều kiện lỗi đó", **không** phải bằng chứng về lỗi thật hoặc về tỉ lệ phát hiện; (b) mutant sống sót cho thấy
**khoảng trống của catalog + seed** (không MR và không seed nào có hai SA cùng tên ở hai namespace). Điều này gợi ý ứng viên MR mới
(thêm RoleBinding cho SA *cùng tên khác namespace*, target SA bất biến) nhưng **chưa thiết kế/chưa chạy**. (c) 1 mutant ≠ mutation score:
**không báo phần trăm**. Một mutation score có nghĩa cần tập mutant chọn trước theo toán tử (bỏ một phép so sánh, đổi `==` thành `!=`,
bỏ một điều kiện kind...) và loại mutant tương đương.

## 6. Known-defect evaluation

Xem `docs/KNOWN_DEFECT_EVALUATION_PLAN.md`. Tóm tắt: hiện **0 mục `ELIGIBLE_FROZEN`**; không tính detection rate.

## 7. Threats to validity

* **Internal:** MR sai ngữ nghĩa (mới có review tác giả); mapping control→target sai; normalizer sai (Trivy PASS suy luận; Kubescape gộp RBAC theo bộ ba); MR-02/05/07 viết sau khi biết hành vi scanner (dẫn dắt).
* **Construct:** VIOLATION ≠ bug; MR PASS ≠ scanner đúng (hai lần quét cùng sai vẫn thỏa `equal`); "PASS" của Trivy là suy luận.
* **External:** 8 seed, hai scanner, hai phiên bản, local-file mode, closed bundle; KALM 65/238 chọn có ưu tiên RBAC; không đại diện Kubernetes thực tế.
* **Conclusion:** n rất nhỏ ở mọi nhóm; không có kiểm định thống kê; không báo specificity/precision/recall.
* **Reproducibility:** phụ thuộc binary và policy bundle đã ghim; Trivy checks bundle được tải một lần (2026-10-28).

## 8. Replication package (thiết kế; mục đã có/chưa có)

| Thành phần | Có? | Vị trí / việc cần làm |
|---|---|---|
| Mã nguồn + test | có | `src/`, `tests/` (tag/commit ghi trong báo cáo) |
| Catalog MR, property, pattern | có | `mrs/*.yaml` |
| Mapping control, pin scanner | có | `config/*.yaml`, `docs/SCANNER_VERSIONS.md` |
| Seed (tổng hợp, lịch sử, candidate) | có | `seeds/` ; chọn KALM: `runs/heldout/selection.json` (kèm sha256 từng manifest) |
| Lock môi trường mỗi run | có | `environment.lock.json` (version, mode, policy digest, mapping digest, python, platform) |
| Lệnh chạy | một phần | `scripts/demo.sh`, `docs/HOW_TO_ADD_AN_MR.md`; **thiếu** một `REPLICATE.md` chạy từ môi trường sạch |
| Raw kết quả + so sánh đã chuẩn hóa + evidence | có | `docs/evidence/*/` có `manifest.json` (sha256) và `case_index.json` |
| Script tái lập kiểm | có | `compare_runs.py`, `snapshot_mr_behavior.py`, `package_run_evidence.py`, `fault_variant_kubescape.py`, `triage_probe.py` |
| Cài scanner pin từ môi trường sạch | **chưa** | script tải đúng phiên bản + kiểm checksum; policy bundle Trivy (digest `b591e919…`) cần nguồn lưu trữ cố định vì tải một lần |
| Container/lockfile Python | **chưa** | `requirements.lock`, Dockerfile Ubuntu 24.04 |
| Sạch dữ liệu cục bộ | **chưa** | raw JSON chứa `/home/<user>/…` (28 tệp); cần bản đã làm sạch kèm bản gốc băm |

Tiêu chí hoàn thành: một người khác, từ môi trường sạch, chạy một lệnh và nhận `compare_runs.py` báo 0 khác biệt với baseline đã băm.
