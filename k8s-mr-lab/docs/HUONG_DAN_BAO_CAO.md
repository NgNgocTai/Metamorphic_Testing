# Hiểu project và cách báo cáo với thầy

## 1. Hiểu project trong 5 câu

1. **Trivy và Kubescape** là công cụ quét cấu hình Kubernetes để tìm lỗi bảo mật. Bản thân chúng cũng có thể **đánh giá sai**.
2. Khó kiểm thử chúng theo cách thường: với một cấu hình phức tạp, **không có sẵn đáp án đúng** để so (test oracle problem).
3. **Metamorphic Testing (MT)** đổi câu hỏi: không hỏi "kết quả đúng là gì?", mà hỏi "nếu đổi cấu hình theo một quy luật mà Kubernetes bảo đảm không ảnh hưởng, kết quả quét phải thay đổi thế nào?".
4. Quy luật đó là một **Metamorphic Relation (MR)**. Mỗi MR làm **hai việc**: sinh cấu hình mới C2 từ cấu hình gốc C1, và là **tiêu chí kiểm tra** kết quả quét C1 và C2 của cùng một scanner.
5. Nếu kết quả vi phạm quan hệ thì đó là **MR violation** (một cảnh báo), rồi mới điều tra xem scanner có thật sự sai không.

### Ví dụ xuyên suốt (MR-02) — đây là cái nên nhớ nhất
- Cấu hình gốc C1: ServiceAccount `app` ở namespace `lab-a` được RoleBinding gán Role `app-role` (chỉ đọc configmaps). Có Deployment `web` dùng `app`.
- Biến đổi: thêm một Role **cùng tên** `app-role` ở namespace **khác** (`lab-a-decoy`), quyền rộng, **không bind** cho ai.
- Theo Kubernetes: RoleBinding chỉ tìm Role trong **namespace của nó**, nên quyền của `app` **không đổi**.
- Vì vậy kết quả quét control đánh giá `web` **phải giữ nguyên**.
- Thực tế (Kubescape v4.0.15): `C-0267` đổi từ passed sang failed → **vi phạm MR**. Lý do tìm được trong rule: nó ghép Role theo **tên**, bỏ qua namespace.

## 2. Framework chạy thế nào (một hàng)

`Seed (cấu hình gốc)` → `MR sinh cấu hình mới` → `kiểm tra cặp hợp lệ` → `quét thật bằng cùng scanner, hai lần` → `chuẩn hóa kết quả` → `MR checker so quan hệ` → `triage` (chạy lại, ghi bằng chứng).

Năm MR và căn cứ (đưa bảng này lên slide "MR được xây dựng thế nào"):

| MR | Biến đổi | Nhóm OWASP K8s Top 10 (2025) | Căn cứ từ tài liệu Kubernetes |
|---|---|---|---|
| MR-01 | đổi thứ tự key YAML | — | thứ tự key không đổi object |
| MR-02 | thêm Role decoy cùng tên, khác namespace | K02 Overly Permissive Authorization | RoleBinding chỉ tham chiếu Role cùng namespace |
| MR-03 | tách verbs của một rule | K02 | quyền RBAC cộng dồn |
| MR-04 | bật `privileged` | K01 Insecure Workload Configurations | Pod Security Standards cấm `privileged` |
| MR-05 | đổi `apiGroups` của quyền secrets | K02, K03 Secrets Management Failures | Secrets thuộc core group `""` |

Chuỗi lập luận để nói: **OWASP K8s Top 10 cho phạm vi rủi ro → tài liệu Kubernetes cho quy tắc → từ quy tắc dẫn xuất MR → framework kiểm thử scanner.**
Cột OWASP là mapping **do đề tài tự gán**, giống bài Web tự gắn mã CWE/OWASP cho MR của họ; ghi rõ là bản **2025** (bản 2022 đánh số khác).
OWASP dùng để *chọn thuộc tính cần kiểm thử*, không dùng để đặt tên cho lỗi tìm được; lỗi tìm được được phân loại theo họ nguyên nhân (ví dụ "ghép Role theo tên, bỏ qua namespace").

## 3. Kết quả — nói đúng những con số này

- 5 MR chạy trên **2 scanner thật** (Trivy 0.75.0, Kubescape v4.0.15), 80 test tự động đều pass (3 test integration cần đúng binary scanner).
- Mỗi scanner: **26 cặp** kiểm thử hợp lệ (21 cặp khác nhau về nội dung).
- **6 cảnh báo vi phạm MR = 4 cặp input khác nhau = 2 họ ứng viên lỗi.** (Không nói "6 lỗi".)
  - Kubescape: `C-0267/C-0272` ghép Role theo tên, bỏ qua namespace (MR-02).
  - Trivy: `KSV-0113` bỏ qua `apiGroups`: Role chỉ có quyền secrets ở group `apps` vẫn bị báo (MR-05).
- Hai ứng viên đều **tái hiện được** và có bằng chứng (raw JSON, rule, thí nghiệm đổi từng yếu tố). **Chưa xác nhận chính thức là lỗi.**
- Đây là kiểm thử **có định hướng**: hai lớp lỗi này đã biết từ trước rồi mới viết MR. **Không phải phát hiện lỗi mới.**

## 4. Kịch bản nói (khoảng 7 phút)

| Phút | Nội dung | Gợi ý |
|---|---|---|
| 1 | Bài toán: scanner cũng có thể sai, khó có đáp án đúng để so | Nêu ví dụ Role trùng tên khác namespace |
| 1 | Vì sao dùng MT; MR vừa sinh test vừa là tiêu chí kiểm tra | Không nói MT là do mình phát minh; bài Web về MT là nền phương pháp, đề tài này áp dụng cho đối tượng khác (scanner) |
| 2 | **Demo MR-02** (xem mục 5) | Chỉ vào: diff chỉ thêm một Role; C-0267 PASS → FAIL |
| 1 | Framework và 5 MR (một sơ đồ + bảng 5 MR) | Không đi vào code |
| 1 | Kết quả và giới hạn (mục 3) | Nói rõ "có định hướng", "chưa confirm" |
| 1 | Kế hoạch tiếp theo và câu hỏi cho thầy | Mục 6 |

## 5. Chuẩn bị demo (làm trước một lần)

```bash
# trong Ubuntu (WSL)
cd /mnt/d/Code/KLTN/Metarmophic_testing/k8s-mr-lab
./scripts/demo_mr02.sh          # khoảng 15 giây, in 6 bước
```
Script in lần lượt: scanner và phiên bản → cấu hình gốc → diff của phép biến đổi → bảng `C-0267 / C-0272` trước và sau → quan hệ kỳ vọng và thực tế → trạng thái `CANDIDATE_REPRODUCED`.
Nếu thầy muốn xem công cụ thứ hai: `./scripts/demo_mr02.sh --scanner trivy --mr MR-05 --out runs/demo_mr05`.
Nên **chạy thử trước một lần** để biết output trông thế nào (thư mục `runs/demo_mr02` do script tự tạo).

## 6. Hỏi thầy gì

1. Hướng MR-first (không dựng oracle độc lập) đã phù hợp chưa?
2. Nên ưu tiên mở rộng nhóm MR nào tiếp theo: ServiceAccount token hay Pod Security?
3. Cần bao nhiêu seed/cấu hình mới để thầy thấy đủ thuyết phục cho phần đánh giá cuối?

## 7. Câu thầy có thể hỏi và cách trả lời

| Câu hỏi | Trả lời ngắn |
|---|---|
| Em dựa vào đâu để chọn và xây MR? | Dùng OWASP Kubernetes Top 10 (2025) để chọn nhóm rủi ro (hiện K01, K02, K03), rồi dẫn xuất MR từ tài liệu chính thức của Kubernetes (RBAC, Pod Security Standards). Mapping MR → nhóm OWASP do đề tài tự gán, giống bài Web gắn CWE cho MR. Bước tiếp theo là duyệt đủ K01–K10 xem nhóm nào viết được MR. |
| Em chỉ áp dụng bài Web sang Kubernetes à? | Kế thừa **phương pháp** MT để giải test oracle problem, nhưng đối tượng khác: kiểm thử **scanner**, MR được dẫn xuất từ quan hệ giữa các resource Kubernetes (Role, Binding, namespace…), không phải từ request Web. Đóng góp cần chứng minh là cách xây MR, tự động sinh test và đánh giá. |
| Không có đáp án đúng thì sao biết scanner sai? | Em không khẳng định ngay. MR violation chỉ là cảnh báo; sau đó em chạy lại, đọc raw JSON, đọc rule của scanner và đổi từng yếu tố để cô lập nguyên nhân. Kết luận cuối là do người đánh giá. |
| Có phải lỗi mới không? | **Không.** Đây là hai lớp lỗi đã biết trước (guided). PoC chứng minh phương pháp tái hiện được chúng; chưa chứng minh phát hiện lỗi mới. |
| Vì sao không so với random testing? | Bài Web không so với random testing; RQ2 của họ so *loại lỗ hổng phát hiện được* với các công cụ security testing hiện có (SOTA). Đề tài đo khả năng áp dụng, hiệu quả phát hiện và chi phí; so với phương pháp khác để ở hướng phát triển sau. |
| Bài Web đo bằng CVE (sensitivity), em đo thế nào? | Ở RQ4 bài Web lấy các lỗ hổng đã có CVE của Jenkins 2.121.1 và Joomla 3.8.7 làm "đáp án", chọn trong đó nhóm mà catalog MR của họ chạm tới và tái hiện được bằng tay (OWASP/CWE thì chỉ là danh mục điểm yếu để họ viết MR ở RQ1/RQ2, không phải đáp án). Lỗi của scanner không có CVE nên em không tính tỉ lệ kiểu đó. Thứ gần nhất là các issue công khai trên GitHub của scanner (như kubescape#2579) và các lớp lỗi lịch sử K1/N2; em báo "tái hiện được hai lớp lỗi đã chọn trước" và phân loại theo họ nguyên nhân, không gọi là tỉ lệ phát hiện. |
| Bài Web có RQ về oracle problem, em có không? | Oracle problem là **động cơ** của đề tài: không có sẵn danh sách finding đúng cho mọi cấu hình. Em **không đặt RQ riêng** để đo "MT giải quyết oracle problem đến đâu". MR chỉ là oracle quan hệ một phần: nó phát hiện vi phạm quan hệ, còn kết luận lỗi vẫn cần người đọc rule và bằng chứng; MR bất biến bỏ sót lỗi mà scanner sai giống nhau ở cả hai đầu vào. RQ1 của em (Applicability) tương ứng gần với RQ3 và RQ2 của bài Web về điều kiện áp dụng và phạm vi. |
| Violation có chắc là bug không? | Không. Có thể do MR sai, do chuẩn hóa sai hoặc do control ngoài phạm vi. Vì vậy có bước triage và các thí nghiệm đổi từng yếu tố (ví dụ: Role decoy khác tên thì không báo, Role local cấp quyền thật thì báo đúng). |
| Số liệu có ít quá không? | Đúng, quy mô PoC (26 cặp/scanner, 7 seed). Mục tiêu giai đoạn này là chứng minh khả thi, chưa phải tỉ lệ tổng quát. |
| Sao có 6 cảnh báo mà chỉ nói 2 lỗi? | Nhiều cảnh báo cùng một nguyên nhân và có seed trùng nội dung. 6 cảnh báo = 4 input khác nhau = 2 họ nguyên nhân giả định. |
| Trivy báo PASS có đáng tin không? | Trivy không gắn PASS vào từng resource, nên em coi đó chỉ là "không thấy FAIL". Kết luận về Trivy dựa trên **FAIL có gắn resource** (MR-05). |
| Sao chỉ chạy quét file, không quét cluster? | Cả hai ứng viên tái hiện được ở chế độ quét file. Live-cluster tốn thêm chi phí dựng và reset; để mở rộng sau. |
| Chi phí thế nào? | Sinh một cặp dưới ~100 ms; một lượt gọi scanner khoảng 1,5 s (Trivy) và 3,7 s (Kubescape). Số lượt quét tiết kiệm được nhờ cache là 26. |
| Bước tiếp theo? | Xác nhận hai ứng viên, thử bản scanner mới hơn, thêm MR cho token và Pod Security, thử trên cấu hình chưa dùng khi thiết kế MR. |

## 8. Đừng nói

- "Em tìm ra 6 lỗi / lỗi mới / zero-day".
- "MR tốt hơn random" (chưa đánh giá).
- "Đã xác nhận" hay "confirmed" (chưa).
- "Phương pháp đã kiểm chứng trên toàn bộ Kubernetes" (mới có RBAC và một phần Pod Security).
- Con số về bài báo Web mà bạn chưa tự đối chiếu với bản gốc.
- "Em viết 5 MR để tìm lỗi Trivy/Kubescape". Nên nói: "em xây phương pháp dẫn xuất và thực thi MR từ ngữ nghĩa bảo mật Kubernetes; Trivy và Kubescape là hai hệ thống thật để đánh giá, giống Jenkins và Joomla trong bài Web".
- "Chưa ai áp dụng MT cho scanner" (chưa khảo sát related work đủ để nói vậy).

## 9. Đọc để nắm sâu hơn (nếu còn thời gian)

`POC_REPORT_FOR_ADVISOR.md` (bản chính thức) → `DEFECT_TRIAGE_RESULTS.md` → `HUONG_DAN_TU_KIEM_TRA.md` (tự làm lại các bước để trả lời trực tiếp nếu thầy hỏi chi tiết).
