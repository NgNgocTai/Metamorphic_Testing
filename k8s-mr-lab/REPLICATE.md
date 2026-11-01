# REPLICATE: tái lập từ môi trường sạch

Mục tiêu: một người khác, từ máy mới, dựng đúng môi trường, chạy lại, và kiểm kết quả với baseline đã băm. Lệnh chạy từ **thư mục `k8s-mr-lab/`** (nơi có `pyproject.toml`).
Mục nào chưa kiểm chứng được từ nguồn cố định được ghi `BLOCKER`; không có checksum nào dưới đây là suy đoán, chúng là số đo trên máy gốc.

## 1. Yêu cầu hệ thống

| | Máy gốc (đã dùng) |
|---|---|
| OS | Ubuntu 24.04.4 LTS trong WSL2 (Windows 11) |
| Python | 3.12.3 |
| Gói Python | `PyYAML 6.0.3`, `pytest 9.2.0` (chỉ hai gói này) |
| Mạng | cần khi cài scanner và tải policy; **không** cần khi chạy (`--skip-check-update`, `--use-artifacts-from`) |
| Dung lượng | ~1 GB (binary + policy) + ~70 MB mỗi run đầy đủ |

Chạy phần **không cần scanner** (unit test, `mr validate`, `seeds`, `mr informative` trên evidence đã lưu) trên Windows/Linux/macOS với Python ≥ 3.10.

## 2. Cài Python và dự án

```bash
cd k8s-mr-lab
python3 -m venv ~/mrlab-venv
~/mrlab-venv/bin/pip install -e '.[dev]'
PY=~/mrlab-venv/bin/python
```

## 3. Cài scanner đúng phiên bản (BLOCKER một phần)

| Scanner | Phiên bản | sha256 binary **đo trên máy gốc** | Nguồn cài |
|---|---|---|---|
| Trivy | 0.75.0 | `93f9da8e4ba5e0c1c76d8234ed2494cf9afb0a96fd21953e424bb795f3299b8e` (`/usr/local/bin/trivy`, 172 765 344 B) | bản phát hành GitHub `aquasecurity/trivy` v0.75.0 |
| Kubescape | v4.0.15 (build `16cfe102f11551a6455fe9bf8e37d7083da90484`, 2026-09-29) | `011569dbcde85afc96cf63262e4f967166b6680fd70a623e9065334b6767b244` (`/usr/local/bin/kubescape`, 292 829 803 B) | bản phát hành GitHub `kubescape/kubescape` v4.0.15 |

* **BLOCKER (một phần):** hai binary pin chính (Trivy 0.75.0, Kubescape v4.0.15) chưa được tải lại từ trang phát hành để so với checksum do nhà phát triển công bố; hai hash ở trên chỉ cho phép **so máy mới với máy gốc**. Riêng Kubescape v4.0.11 và v4.0.12 (KD-001) đã tải lại và khớp `checksums.sha256` chính thức
  (`sha256sum /usr/local/bin/trivy /usr/local/bin/kubescape`). Nếu hash khác (build khác nền tảng) thì kết quả quét có thể khác dù cùng số phiên bản: ghi lại như một khác biệt môi trường.
* Kiểm pin: `k8s-mr-lab versions` (phải ra `OK` cho cả hai).

## 4. Policy bundle (BLOCKER một phần)

| Thành phần | Digest | Cách có |
|---|---|---|
| Trivy checks bundle | `sha256:b591e9190cff4aa4e385b1a25bccfd9ecf178d3c77fd194e1410b7ce7e1df058`, tải 2026-10-28 (`~/.cache/trivy/policy/metadata.json`) | tải một lần bởi Trivy; chạy với `--skip-check-update` để đóng băng. **BLOCKER:** bundle mới tải sau ngày đó sẽ khác; chưa có bản lưu trữ cố định ngoài máy gốc |
| Kubescape artifacts | `8cfb23237b739c2089314ccf61530fbb62a87fb19ff6cd6d9fd252f020b82150` (gộp `allcontrols.json`, `controls-inputs.json`, `exceptions.json` trong `~/.kubescape`) | `kubescape download artifacts` (mặc định lưu `~/.kubescape`). **BLOCKER:** nội dung phụ thuộc thời điểm tải |

Nếu digest trên máy mới khác: **đó là một experiment track khác**; runner từ chối so sánh hai lần quét khác digest (`ENVIRONMENT_MISMATCH`). Đừng trộn kết quả hai track.

## 5. Kiểm tra phần mềm

```bash
$PY -m pytest -q                                        # 3 test integration bị skip nếu thiếu binary; ràng buộc kiến trúc: tests/unit/test_unified_framework.py
$PY -m k8s_mr_lab mr validate                           # cổng CẤU TRÚC: schema, truy vết, mapping/scope, chạy MR trên mọi seed hợp lệ
$PY -m k8s_mr_lab versions                              # Trivy OK, Kubescape OK
# registry sinh từ policy đã pin: sinh lại phải ra đúng tệp đã commit (digest policy lấy từ `versions`)
$PY scripts/derive_control_registry.py --trivy-policies ~/.cache/trivy/policy/content/policies/kubernetes/policies \
    --kubescape-artifacts ~/.kubescape --trivy-policy-digest sha256:b591e9190cff4aa4e385b1a25bccfd9ecf178d3c77fd194e1410b7ce7e1df058 \
    --kubescape-policy-digest 8cfb23237b739c2089314ccf61530fbb62a87fb19ff6cd6d9fd252f020b82150 --out out/control-registry.yaml
diff out/control-registry.yaml config/control-registry.yaml   # kỳ vọng: không khác
```

## 6. Chạy toàn bộ thí nghiệm chính thức

Từ cây mã sạch (đã commit); mỗi lệnh ghi khối `experiment` (commit, digest, loại thí nghiệm) vào `environment.lock.json`.

```bash
MRS="--mr MR-01 --mr MR-02 --mr MR-03 --mr MR-04 --mr MR-05 --mr MR-06 --mr MR-07 --mr MR-08 --mr MR-09"
SEEDS="seeds/synthetic seeds/historical seeds/candidate"
$PY -m k8s_mr_lab seeds coverage --roots $SEEDS --with-mr                                         # coverage seed (tất định)
# 1. baseline: 9 MR, hai scanner
$PY -m k8s_mr_lab run --scanner trivy     --seeds $SEEDS $MRS --experiment-type baseline --experiment-id poc-v2-baseline --out out/trivy
$PY -m k8s_mr_lab run --scanner kubescape --seeds $SEEDS $MRS --experiment-type baseline --experiment-id poc-v2-baseline --out out/kubescape   # ~5 phút
$PY -m k8s_mr_lab triage --run out/trivy --minimize ; $PY -m k8s_mr_lab triage --run out/kubescape --minimize
$PY -m k8s_mr_lab mr informative --run out/trivy out/kubescape --out out/informative
# 2. lỗi lịch sử KD-001: cùng artifacts, hai binary (tải và kiểm checksum: docs/KD001_REPRODUCTION.md; sửa `binary:` trong bản sao scanners.yaml)
$PY -m k8s_mr_lab --config out/scanners-v4.0.11.yaml run --scanner kubescape --seeds $SEEDS --mr MR-02 --experiment-type historical-defect --experiment-id kd001-v4.0.11 --out out/kd001/v4.0.11
$PY -m k8s_mr_lab --config out/scanners-v4.0.12.yaml run --scanner kubescape --seeds $SEEDS --mr MR-02 --experiment-type historical-defect --experiment-id kd001-v4.0.12 --out out/kd001/v4.0.12
# 3. mutation MR-09: bản sao cô lập của artifacts, bỏ verb watch khỏi C-0015 (digest policy khác = track riêng)
$PY scripts/fault_variant_kubescape.py ~/.kubescape out/mut-artifacts --control C-0015 --variant drop-watch-verb
sed "s#~/.kubescape#$PWD/out/mut-artifacts#" config/scanners.yaml > out/scanners-mutant.yaml
$PY -m k8s_mr_lab --config out/scanners-mutant.yaml run --scanner kubescape --seeds $SEEDS --mr MR-09 --experiment-type mutation --experiment-id mr09-drop-watch-mutant --out out/mr09-mutant
# 4. bảng kết quả và tác động migration (sinh từ run, không gõ tay)
$PY scripts/poc_tables.py --trivy out/trivy --kubescape out/kubescape --kd-affected out/kd001/v4.0.11 --kd-fixed out/kd001/v4.0.12 --mutant out/mr09-mutant --out out/poc_tables.md
$PY scripts/migration_impact.py --scanner kubescape --new out/kubescape --old <thư mục run cũ> ... --out out/migration_kubescape   # run cũ: runs/ và docs/evidence/ (chỉ đọc)
```
Luôn đọc `comparisons.csv` (có `role`, `tier`, `basis`, `engaged`), không chỉ `results.csv` (cột verdict của `results.csv` chỉ điền ở dòng VIOLATION).
Held-out (manifest bên thứ ba, đóng băng trước): `python scripts/heldout_prepare.py` rồi `bash scripts/heldout_run.sh` (cần `~/Kalm-Benchmark`).

## 7. Kiểm chứng kết quả

```bash
# so sánh run mới với kết quả chính thức đã commit: cùng case_id phải cùng verdict từng khóa
$PY scripts/compare_runs.py docs/evidence/poc_v2_2026-11-01/trivy out/trivy
$PY scripts/compare_runs.py docs/evidence/poc_v2_2026-11-01/kubescape out/kubescape
# kiểm toàn vẹn gói evidence đã commit: sha256 của từng tệp phải bằng manifest.json cạnh nó
$PY - <<'EOF'
import json, hashlib, pathlib
bad = 0
for m in pathlib.Path("docs/evidence").rglob("manifest.json"):
    d = m.parent
    for rel, v in json.loads(m.read_text())["files"].items():
        bad += hashlib.sha256((d / rel).read_bytes()).hexdigest() != v["sha256"]
print("manifest mismatches:", bad)
EOF
```
`compare_runs.py` so các dòng có mặt ở cả hai. Evidence cũ (PoC trước khi thống nhất: `runs/trivy`, `runs/kubescape`, `docs/evidence/*` trừ `poc_v2_2026-11-01`) là tư liệu kiểm toán, **không** phải baseline để so; tác động của việc thống nhất: `docs/poc/MIGRATION_IMPACT_REPORT.md`.

## 8. Kết quả kỳ vọng (từ máy gốc, commit `aa40b76`)

| Kiểm tra | Kỳ vọng |
|---|---|
| `pytest` có scanner | tất cả pass, 0 skip (224 test) |
| `k8s-mr-lab versions` | Trivy `OK`, Kubescape `OK` |
| `mr validate` | 9 MR, 0 error, 0 warning |
| Baseline 9 MR | Trivy: `PASS 24, SKIP 47, VIOLATION 1, INVALID_SOURCE 1`; Kubescape: `PASS 30, SKIP 36, VIOLATION 6, INCONCLUSIVE 3, PARTIAL 1, INVALID_SOURCE 1` |
| KD-001 (MR-02) | v4.0.11: `VIOLATION 7, PASS 1`; v4.0.12: `VIOLATION 5, PASS 3`; 28/64 khóa aggregator khác nhau, chỉ ở verdict follow-up |
| Mutation MR-09 | mutant: `VIOLATION 1, PASS 2` (pinned: `PASS 3`); chỉ case đích `[watch]` |
| Triage | 7 alert `CANDIDATE_REPRODUCED`, 0 confirmed |

## 9. Danh sách đối chiếu môi trường mới ↔ gốc

| Mục | Gốc | Mới (điền) | Khớp? |
|---|---|---|---|
| OS / Python | Ubuntu 24.04.4 / 3.12.3 | | |
| sha256 `trivy` | `93f9da8e…299b8e` | | |
| sha256 `kubescape` v4.0.15 | `011569db…67b244` | | |
| sha256 `kubescape` v4.0.11 / v4.0.12 | `9f3fd186…e5c0a9` / `58e9840d…af61fa` (khớp `checksums.sha256` chính thức) | | |
| `trivy --version` | 0.75.0 | | |
| `kubescape version` build commit | `16cfe102…84da90484` | | |
| digest Trivy checks | `b591e919…1df058` | | |
| digest Kubescape artifacts | `8cfb2323…20b82150` | | |
| `PyYAML` / `pytest` | 6.0.3 / 9.2.0 | | |
| `mr validate` | 9 MR, 0 error | | |
| `registry_matches_policy` trong lock | `true` | | |

Một dòng không khớp không làm kết quả sai, nhưng nghĩa là đang chạy một track thí nghiệm khác và phải ghi rõ.

## 10. Xử lý sự cố

* `SCAN_ERROR … version pin violated`: binary không đúng phiên bản trong `config/scanners.yaml`.
* `ENVIRONMENT_MISMATCH`: hai lần quét khác policy digest (policy đổi giữa chừng). Tải policy trước, đóng băng, chạy lại.
* Trivy báo thiếu bundle khi offline: chạy một lần `trivy config` có mạng để lấy checks bundle (rồi dùng `--skip-check-update`).
* `unknown MR id` (mã thoát 2): MR candidate cần `--mr MR-06` v.v.; id gõ sai.
* Windows: dùng WSL cho scanner; unit test không cần scanner chạy được trên Windows.
* Trong WSL, `/tmp` có thể bị dọn khi WSL tắt: ghi kết quả vào thư mục bền (ví dụ trong repo, ngoài các thư mục được git theo dõi).

## 11. Giới hạn tái lập

* Hai BLOCKER (mục 3, 4): chưa có nguồn cố định, có checksum công bố, cho binary và policy; đó là rào cản chính cho tái lập từ máy sạch.
* Bằng chứng gốc chứa đường dẫn máy gốc (xem `docs/EVIDENCE_SHARING_AUDIT.md`); dùng `scripts/sanitize_evidence.py` để tạo bản public.
* Chưa có container/lockfile Python; phụ thuộc chỉ gồm PyYAML và pytest nên rủi ro thấp.
* Chưa chạy lại toàn bộ quy trình trên máy hoàn toàn sạch: tài liệu này mô tả máy gốc và các bước, chưa phải kết quả của một lần tái lập độc lập.
