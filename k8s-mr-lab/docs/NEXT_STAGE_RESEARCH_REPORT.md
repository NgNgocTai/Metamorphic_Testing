# Báo cáo giai đoạn nghiên cứu tiếp theo (2026-11-01)

Nguyên tắc đọc: mọi con số có nguồn trong `docs/evidence/` hoặc là kết quả lệnh được ghi; phân biệt **đã chạy với scanner thật** (Trivy 0.75.0, Kubescape v4.0.15), **chỉ cấu trúc/không cần scanner**, và **đề xuất**.
Chưa commit, chưa push, chưa đổi lịch sử Git.

## 1. Hiện trạng so với yêu cầu trước

Baseline PoC được bảo toàn: MR-01..05 cho cùng kết quả (Trivy 256/256, Kubescape 386/386 phép so sánh control×resource, chạy lại trong lượt này với đủ seed và cả MR candidate), snapshot hành vi MR-01..05 giống hệt,
gói evidence PoC 138/138 sha256 khớp (kiểm ở lượt trước). Không sửa adapter, normalizer, checker, golden, pin scanner.

## 2. Thay đổi đã làm

| File | Thay đổi | Lý do | Kiểm chứng |
|---|---|---|---|
| `scripts/sanitize_evidence.py`, `docs/EVIDENCE_SHARING_AUDIT.md` | công cụ làm sạch có truy vết + kiểm toán | P0: dữ liệu cá nhân trước khi chia sẻ | 667 tệp, 0 lệch hash gốc, 571 tệp giống byte, 0 chuỗi sót; test |
| `README.md`, `docs/HUONG_DAN_*.md` | `cd` trước `pip install -e`, bỏ đường dẫn cứng, danh sách MR/doc | P0 | test liên kết tài liệu |
| `mrs/security_properties.yaml`, `mr_tools.py`, tests, docs | `verified` định nghĩa chặt; mục CIS từ artifact scanner ⇒ `verified: false` + `basis` | P0: không gọi CIS đã xác minh khi chưa đọc tài liệu CIS | test; `mr validate` bắt thiếu `basis` |
| `src/k8s_mr_lab/informative.py`, `config/control-registry.yaml`, `scripts/derive_control_registry.py`, `mr informative` | phân tầng comparison theo khả năng quan sát | P1: PASS có mang thông tin không | 11 test; chạy trên evidence thật |
| `mr review-packet`, `docs/INDEPENDENT_MR_REVIEW_PROTOCOL.md`, `docs/review_packets/` | hồ sơ review độc lập MR-02/07/08, quyết định để trống | P1 | test không ghi quyết định |
| `config/policy-mapping.yaml` | bỏ ánh xạ Trivy cho MR-07; thêm MR-08 (Kubescape workload-level) | Trivy MR-07 0/20 mang thông tin | `mr informative` |
| `src/k8s_mr_lab/seeds.py`, `k8s-mr-lab seeds ...`, `SEED_COVERAGE_REPORT.md`, `SOURCE_INPUT_GENERATION_V2.md` | kiểm kê, coverage 52 token, chọn tham lam tất định, chia dev/eval | P2 | 9 test; chạy trên seed dự án và KALM |
| `transforms/rbac_subject_namespace_shift.py`, catalog, property, helper `k8s.other_bindings_naming_sa` | MR-08 (candidate) | P2: lấp khoảng trống mutant | 6 test + thí nghiệm có đối chứng |
| `docs/MUTATION_GAP_ANALYSIS.md`, `SUBJECT_NAMESPACE_MR_CANDIDATE.md`, evidence `mr08_mutation_2026-11-01` | đọc lại thí nghiệm mutant; MR-08 giết mutant | P2 | 2 lượt chạy cùng case_id/sha256 |
| `docs/KNOWN_DEFECT_CATALOG.md`, `RQ2_EFFECTIVENESS_PROTOCOL.md`, `EVALUATION_PROTOCOL_V2.md` (sửa) | nguồn chính thức, giao thức RQ2 | P3 | đọc API GitHub công khai |
| `REPLICATE.md` | tái lập từ môi trường sạch, sha256 binary đo được | P4 | chưa chạy trên máy sạch |

## 3. Cải tiến khoa học và cái chỉ là refactor/tài liệu

**Tăng tính đúng đắn / khả năng kiểm chứng:**
* Tầng comparison: tách "MR PASS" khỏi "MR PASS mang thông tin" bằng tiêu chí khách quan từ policy đã pin.
* Đọc lại thí nghiệm mutant: số đúng là 30 cặp được quét, 21/404 khóa trên control bị đột biến, **0/404 khóa khác** ⇒ mutant *không được kích hoạt*, không phải "MR kém" (sửa một cách nói sai trước đó).
* MR-08 và thí nghiệm có đối chứng, dự đoán viết trước.
* Phát hiện `verified` bị dùng quá mức cho CIS và sửa.
* Coverage seed có mẫu số cố định: 17/52 token cho 6 seed duy nhất (không phải 8).

**Chỉ là tài liệu/hạ tầng:** `REPLICATE.md`, review packet, giao thức RQ2, audit chia sẻ, walkthrough.

## 4. MR-07

* **Ngữ nghĩa:** hai biểu diễn là cùng danh tính theo trích dẫn đã xác minh về username `system:serviceaccount:ns:name`; bước "subject `User` khớp username" là cách RBAC hoạt động nhưng **không có câu trích riêng** (ghi rõ).
* **Phạm vi control:** `C-0267/C-0272` quan sát subject (join `kind == "ServiceAccount"`, `.name`, `.namespace`); `C-0015/0007/0035` ở mức Role. **Trivy không có control quan sát.**
* **Trivy:** 0/20 so sánh mang thông tin ⇒ **đã bỏ ánh xạ Trivy cho MR-07**.
* **Kubescape:** `C-0267` FAIL→PASS trên `Pod/lab-c/reader-pod`, verdict tường minh, diff đúng một subject.
* **Triage:** `CANDIDATE_REPRODUCED`, họ `kubescape:MR-07:FAIL->PASS`, chưa khớp issue đã biết.
* **Còn bất định:** hợp đồng control nói về *quyền của service account* (mà dạng `User` cũng mang lại), nhưng rego chỉ join `kind == "ServiceAccount"`. Giữa *giới hạn có chủ đích* và *false negative*: **`UNRESOLVED`**. MR-07 được viết sau khi đọc rego (dẫn dắt).

## 5. Khoảng trống mutation

Mutant bỏ so sánh namespace của subject sống sót vì **không đầu vào nào kích hoạt nó** (không có SA cùng tên khác namespace; không MR cũ làm workload phụ thuộc namespace subject). MR-08 làm workload phụ thuộc đúng điều đó:
trên cùng case và sha256, scanner gốc cho `C-0267` FAIL→PASS (quan hệ thỏa) và mutant cho FAIL→FAIL (**VIOLATION**).
Giới hạn: MR-08 viết **sau và nhắm đúng** mutant; 1 case, 1 mutant, 1 control. Không có mutation score.

## 6. Seed

6 seed duy nhất hợp lệ (8 thư mục: 1 trùng, 1 cố ý hỏng); 17/52 token. Thiếu: ClusterRole/ClusterRoleBinding, subject User/Group, initContainers, automount, multi-namespace, cross-namespace subject.
KALM cục bộ (238 manifest; trùng nội dung 65/65 tệp PoC đã chọn sau chuẩn hóa CRLF): 40/52 token nhưng MR cấp subject chỉ áp dụng được trên 2–3/236 seed và **không manifest nào có chuỗi workload→SA→binding→Role**.
Kế hoạch có thể thực thi: seed lấp token theo MR → ghép bundle liên kết → chia dev/eval.

## 6b. Mang thông tin (tóm tắt)

Trivy 184/310 (0,594) informative, 66 weak, 60 uninformative; Kubescape 448/458 (0,978, **cận trên**), 6 uninformative, 4 inconclusive. Trivy MR-02: **0/40**. Chi tiết: `INFORMATIVE_COMPARISON_ANALYSIS.md`.

## 7. Sẵn sàng đánh giá

| RQ | Trạng thái |
|---|---|
| RQ1 Applicability | đo được tĩnh: applicability theo MR và coverage seed, informative; **thiếu seed**, nguồn ngoài chưa dùng |
| RQ2 Effectiveness | giao thức xong; số hiện có: 3 họ ứng viên, 0 confirmed, 0 known-defect đủ điều kiện, 1 mutant bị MR nhắm đúng giết; **không có tỉ lệ nào** |
| RQ3 Efficiency | chưa tổng hợp bảng chi phí (có `gen_ms`, `scan_ms`, `cache_hits` trong `results.csv`) |

## 8. Test

| Môi trường | Lệnh | Kết quả |
|---|---|---|
| Windows (không scanner) | `PYTHONPATH=src python -m pytest tests -q` | **187 passed, 3 skipped** (3 test integration cần binary) |
| WSL Ubuntu 24.04, Trivy 0.75.0 + Kubescape v4.0.15 thật | `python -m pytest -q` | **189 passed, 0 skipped** (đo trước khi thêm 1 test `--sanitize` ở cuối; xem ghi chú) |
| WSL | `k8s-mr-lab versions` | Trivy OK, Kubescape OK (digest policy `b591e919…`, `8cfb2323…`) |
| WSL | `k8s-mr-lab mr validate` | 8 MR, 0 error, 0 warning (seed invalid được liệt kê và bỏ qua) |
| WSL | `scripts/snapshot_mr_behavior.py` vs baseline | MR-01..05 **IDENTICAL** |
| WSL | kiểm manifest toàn bộ `docs/evidence` | 889 mục, **0 lệch hash** |
| WSL | chạy lại toàn bộ seed + MR candidate, so với run PoC | Trivy 256/256, Kubescape 386/386 giống hệt (run mới có thêm so sánh từ seed/MR bổ sung) |
| WSL | triage + ablation | giống hệt PoC (lượt kiểm trước, `p0_reverification_2026-11-01`) |

Scanner thật (không mock) cho mọi lượt chạy ở trên. Số test Windows/WSL lệch nhau chỉ vì 3 test integration; số cuối WSL cần chạy lại sau khi thêm test mới nhất (một test `--sanitize`, đã pass riêng trên Windows).

## 9. Giới hạn

Mọi property `author_reviewed`; chưa review độc lập. MR-02/05/07/08 viết sau khi biết hành vi scanner. n rất nhỏ. Kubescape informative là cận trên. Danh mục known-defect chưa đầy đủ (giới hạn tốc độ API). `REPLICATE.md` chưa chạy trên máy sạch; binary và policy chưa có nguồn cố định có checksum công bố.
Lịch sử Git (đã push) vẫn chứa username Linux trong evidence/golden và email trong metadata commit.

## 10. Bảng hoàn thành

| Task | Trạng thái | Evidence | Việc tiếp |
|---|---|---|---|
| P0 audit chia sẻ dữ liệu | DONE (xử lý lịch sử: cần bạn quyết) | `EVIDENCE_SHARING_AUDIT.md` | quyết private/public |
| P0 README/docs, `verified` | DONE | commit sau | |
| P0 regression | DONE (xem mục 8) | `docs/evidence/`, mục 8 | |
| P1 giao thức review độc lập + packet | DONE; **PENDING_INDEPENDENT_REVIEW** | `docs/review_packets/` | tìm reviewer |
| P1 MR-07 | DONE phân tích; kết luận `UNRESOLVED` | `MR_CANDIDATE_EVALUATION.md` | đọc tài liệu control / hỏi upstream |
| P1 informative comparisons | DONE (báo cáo, không đổi checker) | `INFORMATIVE_COMPARISON_ANALYSIS.md` | |
| P2 seed coverage + tool | DONE (prototype) | `SEED_COVERAGE_REPORT.md` | thêm seed lấp token |
| P2 MR mới cho khoảng trống | DONE: MR-08 candidate | `SUBJECT_NAMESPACE_MR_CANDIDATE.md` | review độc lập |
| P2 mutation | PARTIAL: 1 mutant, không có score | `MUTATION_GAP_ANALYSIS.md` | bộ toán tử chọn trước, cả Trivy |
| P3 known-defect catalog | PARTIAL: 1 mục SOURCE_VERIFIED, 0 eligible | `KNOWN_DEFECT_CATALOG.md` | tra tay Trivy/K1/N2, bản trước sửa |
| P3 RQ protocol | DONE | `RQ2_EFFECTIVENESS_PROTOCOL.md` | |
| P4 `REPLICATE.md` | PARTIAL: chưa chạy trên máy sạch; 2 BLOCKER | `REPLICATE.md` | nguồn cố định cho binary và policy |

## 11. Ưu tiên tiếp theo

1. Tìm reviewer độc lập cho MR-02/07/08 (mở khóa kết luận ngữ nghĩa).
2. Adjudicate K1/N2/MR-07: đọc mô tả control, tra upstream, thử Kubescape 4.0.16/17 và Trivy 0.76.1 (track riêng).
3. Lấp seed theo token thiếu và ghép bundle liên kết từ KALM; chạy lại RQ1.
4. Bộ mutant chọn trước (Kubescape và Trivy) để có mutation score có nghĩa.
5. Cố định nguồn binary/policy để `REPLICATE.md` chạy được từ máy sạch.

## 12. Tóm tắt cho giảng viên (2–3 phút)

Trước đây MR được viết theo trực giác rồi mới nhìn kết quả. Giờ mỗi MR đi qua chuỗi requirement → property (có trích dẫn tài liệu Kubernetes) → pattern → MR, có phản ví dụ và cổng tự động, nhưng cổng đó chỉ kiểm cấu trúc.
Đóng góp phương pháp mới của lượt này là tách *PASS có nghĩa* khỏi *PASS theo cấu trúc* bằng mô hình đầu vào của control đọc từ policy đã pin: Trivy không thể bị MR-02 thử vì check của nó chỉ nhìn một tài liệu, và đó là điều số PASS thô che giấu.
Thí nghiệm đột biến cho thấy catalog và seed còn một lỗ hổng: một mutant sống sót vì không đầu vào nào kích hoạt nó. MR-08 lấp lỗ hổng đó và giết được mutant, nhưng MR-08 được viết sau và nhắm đúng mutant nên chỉ chứng minh độ nhạy, không chứng minh tỉ lệ phát hiện.
Bằng chứng thực nghiệm: baseline tái lập 256/256 và 386/386; 3 họ hiện tượng cần adjudication, 0 lỗi được xác nhận. Giới hạn: 6 seed duy nhất, mọi property mới chỉ do tác giả review, chưa có lỗi đã biết đủ điều kiện để tính tỉ lệ.
Bước tiếp theo: review độc lập, adjudicate K1/N2/MR-07, mở rộng seed và tập mutant chọn trước.

## 13. Bổ sung: PoC theo tư duy MST-wi (yêu cầu → MR, lỗi đã biết)

**Giai đoạn 1 (`REQUIREMENTS_TO_MR_MATRIX.md`).** 10 yêu cầu cụ thể từ K01/K02, trích nguyên văn từ tài liệu Kubernetes (PSS Baseline, RBAC Good Practices), chốt *trước* khi xem kết quả scanner. Bốn nguồn: OWASP K8s Top 10, CWE, tài liệu Kubernetes, control Trivy/Kubescape.
Kết quả: 3/10 có MR đầy đủ (2 cũ + 1 **dẫn xuất mới**), 1/10 một phần, 4/10 có thể dẫn xuất nhưng chưa cài, 2/10 chưa khả thi (`CONTRACT_NOT_READ`, `RELATION_NOT_SUPPORTED`). Cột `origin` tách MR cũ (chỉ được gắn nhãn) khỏi MR dẫn xuất từ yêu cầu.
MR-09 (R08, `get/list/watch` Secrets) được dẫn xuất từ một câu trích và hợp đồng control, dự đoán viết trước: mọi dự đoán đúng; không có violation ở scanner đã pin; mutant `drop-watch-verb` (chọn từ câu trích, không từ quan sát) bị phát hiện ở đúng 1 trong 3 cặp; so sánh Trivy mang thông tin 3/3. Pattern mới KP4 (giả thuyết, 1 thể hiện) xuất hiện từ ma trận phần tử.

**Giai đoạn 2 (`KD001_REPRODUCTION.md`).** Lỗi kubescape#2579, sửa `opa-utils#177` (tag đầu `v0.0.302`): Kubescape v4.0.11 (`opa-utils v0.0.301`, trước sửa) so với v4.0.12 (`v0.0.303`, sau sửa); binary khớp checksum chính thức; cùng artifacts và cùng sha256 đầu vào.
Phát hiện: **MR-02 với mapping hiện tại không phát hiện lỗi này**; với phạm vi mở rộng (ServiceAccount, RoleBinding) thì phát hiện, 28/114 khóa khác nhau chỉ ở verdict follow-up. Đây là ca DEV (cùng lớp lỗi với K1), không tính vào tỉ lệ độc lập.
**Chưa làm:** tìm lỗi đã biết độc lập thứ hai; cài các yêu cầu R03/R04/R07/R10; quyết định có áp dụng mapping mở rộng cho MR-02 vào baseline hay không.
