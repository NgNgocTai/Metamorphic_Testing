# Kiểm toán dữ liệu trước khi chia sẻ công khai (2026-11-01)

Phạm vi: mọi tệp **được git theo dõi** trong `k8s-mr-lab/` tại HEAD, cộng metadata commit. `runs/` bị `.gitignore` nên không nằm trong repo.
Lệnh kiểm: `git grep` các mẫu đường dẫn máy, định danh, và định dạng credential; công cụ `scripts/sanitize_evidence.py --check DIR`.
Không rewrite lịch sử, không push.

## 1. Kết quả

| Loại | Phát hiện | Mức độ | Cần thiết cho provenance? |
|---|---|---|---|
| Credential thật (GitHub token, AWS key, khóa riêng tư, JWT, Slack token) | **không có** | n/a | n/a |
| Từ khóa "password / token / secret / api-key" | 118 lần, **đều là danh sách từ khóa trong input của control Kubescape** (`sensitiveKeyNames`), không phải giá trị bí mật | không | n/a |
| Tên người dùng Linux `ngoctai` trong `/home/ngoctai/...` | **96 tệp** trong `docs/evidence/` (102 lần) + **14 tệp** `tests/golden/` (đường dẫn `controlsInputs` trong report Kubescape); 0 nơi khác | thấp: lộ username máy WSL, không phải mật khẩu | **không**: chỉ cho biết artifacts nằm ở thư mục nào trên máy chạy. Thông tin quan trọng (version, mode, policy digest) nằm ở trường khác |
| Đường dẫn Windows `D:\Code\KLTN\Tools` | 4 tệp tài liệu (`DEFECT_TRIAGE_RESULTS`, `HUONG_DAN_TU_KIEM_TRA`, `SCANNER_VERSIONS`, `KNOWN_DEFECT_EVALUATION_PLAN`) | rất thấp: tên thư mục | không (chỉ gợi ý nơi có binary khác) |
| `cd /mnt/d/Code/...` trong hướng dẫn | 2 tệp | rất thấp | không: **đã sửa** thành `cd k8s-mr-lab` |
| Email | trong tệp: **không có**. Trong **metadata commit**: 21 commit có tác giả `ngoctaidev <ngocthang8079@gmail.com>` | trung bình nếu repo công khai (địa chỉ email cá nhân hiển thị trên GitHub) | n/a |

Số liệu do lệnh trên cho ra ở HEAD `4ca941e` (+ các sửa đổi chưa commit của phiên này).

## 2. Phân biệt provenance cần thiết với thông tin cá nhân

Cần giữ để tái lập: phiên bản scanner, mode, **policy digest**, mapping digest, sha256 của source/follow-up, lệnh đã chạy (`invocation-*.json`),
raw scanner JSON. Không cần: tên người dùng Linux, thư mục home. Vì vậy thay `/home/ngoctai` bằng `/home/USER` **không làm mất bằng chứng**,
nhưng làm đổi sha256 của các tệp bị sửa, nên **bản gốc không được sửa tại chỗ**.

## 3. Cách xử lý đã làm

* **Giữ nguyên bản gốc** (hash trong `manifest.json` của từng gói vẫn đúng; `tests/golden/` là fixture đóng băng nên không sửa).
* Công cụ **`scripts/sanitize_evidence.py SRC OUT`** tạo bản public riêng: chỉ thay các chuỗi trong `RULES` (home Linux, đường dẫn dự án Windows/WSL, hồ sơ người dùng Windows),
  chỉ trên tệp văn bản; tệp khác sao chép nguyên byte. `OUT/SANITIZATION.json` ghi cho **mỗi tệp**: sha256 gốc, sha256 bản sạch, số lần thay ⇒ truy vết được từ tệp public về tệp gốc.
* Kiểm chứng trên `docs/evidence/`: 667 tệp, 96 tệp bị đổi (102 thay thế), **0 chuỗi còn sót** ở bản sao, mọi JSON vẫn hợp lệ, 571 tệp giống hệt từng byte,
  hash gốc ghi trong bản ghi khớp 100% tệp hiện có. `mr explain --case` chạy bình thường trên bản sạch.
* **Không commit bản sao** (17 MB, nhân đôi dung lượng repo). Tạo khi cần: `python scripts/sanitize_evidence.py docs/evidence docs/evidence_public`
  (đầu ra không được ghi đè; thư mục đích phải chưa tồn tại).

## 4. Rủi ro lịch sử Git (chưa xử lý; cần bạn quyết)

* Remote `origin` (`NgNgocTai/Metamorphic_Testing`) **đã nhận** các commit có 96 tệp evidence chứa `/home/ngoctai`, và các tệp golden từ commit PoC trước đó (`860d5b6`, 2026-10-30). Xóa khỏi cây làm việc **không** xóa khỏi lịch sử.
* Mình **không biết repo đang public hay private** (không có `gh` trong máy). Nếu private: rủi ro thấp, không cần làm gì thêm.
* Nếu public và bạn muốn loại bỏ username/email:
  1. Đơn giản nhất: GitHub → Settings → Emails → bật *Keep my email addresses private* và *Block command line pushes that expose my email*; các commit **tương lai** dùng email noreply. Commit đã có thì vẫn giữ email cũ.
  2. Xóa hẳn khỏi lịch sử cần `git filter-repo` (viết lại lịch sử, đổi mọi hash, buộc force-push, làm hỏng tag `poc-v1.0.0` và commit được trích dẫn trong tài liệu). **Không khuyến nghị** cho một username Linux; chỉ cân nhắc nếu repo public và email là mối lo thật.
* Mức rủi ro đánh giá: username Linux không cho phép truy cập gì; email đã nằm trong metadata của mọi commit từ trước phiên này.

## 5. Việc nên làm trước khi công khai repo

1. Quyết định private/public; nếu public, chọn phương án ở mục 4.
2. Khi phát hành bản nghiên cứu: chạy `sanitize_evidence.py`, đưa **bản public** vào gói phát hành, và giữ bản gốc kèm `SANITIZATION.json` làm đối chiếu.
3. Đừng thêm đường dẫn tuyệt đối vào tài liệu mới (test `test_docs_reference_existing_files_and_cli_commands` chưa kiểm điều này; `sanitize_evidence.py --check docs` kiểm được).

## 6. Cập nhật cuối giai đoạn (evidence mới)

* Các gói evidence **tạo trong giai đoạn này** (`informative_2026-11-01`, `mr08_mutation_2026-11-01`) đã được đóng gói bằng `package_run_evidence.py --sanitize`: đường dẫn máy bị thay **trước khi tính hash**,
  `manifest.json` ghi `"sanitized": true` và `original_sha256` cho từng tệp bị đổi (truy về lượt chạy gốc, vốn nằm trong `runs/` bị git bỏ qua). Quét: **0 hit**.
  (Lượt chạy gốc ghi đường dẫn tuyệt đối `/mnt/d/.../k8s-mr-lab` vì dùng `--out` tuyệt đối; nếu không làm sạch thì thêm khoảng 770 hit.)
* Các gói **đã commit trước đó** (`mr_patterns_verification`, `p0_reverification`, `mr07_dev`, `fault_variants`) vẫn chứa `/home/<user>`: 102 hit trong 96 tệp (số cũ), không sửa tại chỗ để không đổi hash.
* Tài liệu văn xuôi: đã thay `D:\Code\KLTN\Tools` bằng `<TOOLS_DIR>` ở 4 tệp; các hit còn lại trong `docs/*.md` chỉ là chính tài liệu này (trích mẫu để mô tả).
* Biểu thức quét `/home/` nay yêu cầu tên bắt đầu bằng ký tự chữ-số để không báo nhầm chuỗi minh họa `/home/...`.
* `docs/evidence_public/` **chưa được tạo/commit**; tạo bằng `python scripts/sanitize_evidence.py docs/evidence docs/evidence_public` khi cần phát hành.
