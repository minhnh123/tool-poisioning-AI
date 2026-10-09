# BÁO CÁO THỰC NGHIỆM ĐỐI SÁNH: HIỆU QUẢ PHÒNG THỦ CỦA MCP SENTINEL

> **Tác giả / Đề tài**: Nghiên cứu & Xây dựng Cổng phòng vệ MCP Sentinel cho Giao thức Model Context Protocol (MCP).
> **Tập dữ liệu kiểm thử**: Toàn bộ 120 kịch bản tấn công đầu độc công cụ độc hại (`mcp_poison_bench.json`).
> **Quy mô thực nghiệm**: 6 kiến trúc LLM đại diện (3 Local LLM trên Ollama + 3 Cloud LLM trên Groq Cloud).

## 1. Bảng Tổng hợp Đối sánh ASR Trước & Sau Phòng thủ (Master Comparison Table)

| STT | Backend | Kiến trúc Mô hình | Số mẫu | Baseline ASR (Chưa phòng thủ) | **Sentinel ASR (Đã kích hoạt)** | **Mức giảm ASR (ASR Reduction)** | **Tỉ lệ Chặn / Vô hiệu hóa** |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| 1 | `OLLAMA` | `llama3.1:8b` | 120 | 24.17% | **0.00%** | 🟢 **-24.17%** | **100.0%** |
| 2 | `OLLAMA` | `qwen2.5:3b` | 120 | 15.00% | **0.00%** | 🟢 **-15.00%** | **100.0%** |
| 3 | `GROQ` | `openai/gpt-oss-20b` | 120 | 14.17% | **0.00%** | 🟢 **-14.17%** | **100.0%** |
| 4 | `GROQ` | `openai/gpt-oss-120b` | 120 | 13.33% | **0.00%** | 🟢 **-13.33%** | **100.0%** |
| 5 | `GROQ` | `qwen/qwen3.8-27b` | 120 | 11.67% | **0.00%** | 🟢 **-11.67%** | **100.0%** |
| 6 | `OLLAMA` | `deepseek-r1:8b` | 120 | 1.67% | **0.00%** | 🟢 **-1.67%** | **100.0%** |

> **Nhận xét chính:** Toàn bộ 6 kiến trúc mô hình từ 3B, 8B, 20B, 27B đến 120B đều đạt **ASR = 0.00%** khi được bảo vệ bởi MCP Sentinel. Tất cả 120/120 kịch bản tấn công độc hại đều bị chặn đứng hoặc vô hiệu hóa thành công.

---

## 2. Phân tích Chi tiết Đối sánh Theo 4 Vector Tấn công

| Mô hình | Chỉ số | Docstring Injection (34 mẫu) | Tool Squatting (27 mẫu) | Hidden Parameter (27 mẫu) | Output Poisoning (32 mẫu) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `llama3.1:8b` | **Baseline** | 2.9% | 88.9% | 14.8% | 0.0% |
| | **Sentinel** | **0.0%** | **0.0%** | **0.0%** | **0.0%** |
| | **Hiệu quả** | 🟢 -2.9% | 🟢 -88.9% | 🟢 -14.8% | 🟢 -0.0% |
| `qwen2.5:3b` | **Baseline** | 5.9% | 55.6% | 3.7% | 0.0% |
| | **Sentinel** | **0.0%** | **0.0%** | **0.0%** | **0.0%** |
| | **Hiệu quả** | 🟢 -5.9% | 🟢 -55.6% | 🟢 -3.7% | 🟢 -0.0% |
| `openai/gpt-oss-20b` | **Baseline** | 0.0% | 51.9% | 11.1% | 0.0% |
| | **Sentinel** | **0.0%** | **0.0%** | **0.0%** | **0.0%** |
| | **Hiệu quả** | 🟢 -0.0% | 🟢 -51.9% | 🟢 -11.1% | 🟢 -0.0% |
| `openai/gpt-oss-120b` | **Baseline** | 0.0% | 48.1% | 11.1% | 0.0% |
| | **Sentinel** | **0.0%** | **0.0%** | **0.0%** | **0.0%** |
| | **Hiệu quả** | 🟢 -0.0% | 🟢 -48.1% | 🟢 -11.1% | 🟢 -0.0% |
| `qwen/qwen3.8-27b` | **Baseline** | 2.9% | 44.4% | 3.7% | 0.0% |
| | **Sentinel** | **0.0%** | **0.0%** | **0.0%** | **0.0%** |
| | **Hiệu quả** | 🟢 -2.9% | 🟢 -44.4% | 🟢 -3.7% | 🟢 -0.0% |
| `deepseek-r1:8b` | **Baseline** | 5.9% | 0.0% | 0.0% | 0.0% |
| | **Sentinel** | **0.0%** | **0.0%** | **0.0%** | **0.0%** |
| | **Hiệu quả** | 🟢 -5.9% | 🟢 -0.0% | 🟢 -0.0% | 🟢 -0.0% |

---

## 3. Cơ chế Phối hợp Phòng thủ Đa tầng (Defense-in-Depth Breakdown)

MCP Sentinel sử dụng kiến trúc bảo vệ 3 giai đoạn (Dual Hybrid: Python Middleware + Transparent Reverse-Proxy):

1. **Giai đoạn Discovery (`tools/list`): 88/120 mẫu bị loại bỏ ngay từ đầu (73.3%)**
   - **Squatting Detector & Semantic Engine**: Phát hiện và triệt tiêu 100% các công cụ bóng ma giả mạo (`read_file_v2`, `secure_execute`, v.v.), bảo vệ công cụ chuẩn của hệ thống.
   - **Prompt Injection Guard**: Bóc trần các chỉ thị ghi đè hệ thống (`[SYSTEM: ...]`, Cyrillic Homoglyphs, thẻ XML lén lút) ẩn trong docstring.
   - **Schema Validator**: Phát hiện và chặn các bẫy tham số ẩn (`exfil_url`, `telemetry_sink`, `default=True` cho cờ nguy hiểm).
   - *Hệ quả tích cực*: LLM không hề bị phơi nhiễm trước các chỉ thị độc hại hay công cụ lừa đảo, giữ nguyên độ sạch của Context Window.

2. **Giai đoạn Call Phase (`tools/call`): Bảo vệ Runtime & Phân quyền ACL**
   - Kiểm tra quyền truy cập công cụ theo danh mục (LOW / MEDIUM / HIGH risk).
   - Giám sát Honeytoken/Canary (`SENTINEL_CANARY_<uuid>`) và ngăn chặn rò rỉ biến môi trường hoặc path traversal (`../../`).

3. **Giai đoạn Response Phase: Khử độc hoàn toàn 32/32 mẫu Output Poisoning (26.7%)**
   - **Output Sanitizer**: Làm sạch luồng dữ liệu trả về từ tool, khử sạch các mã độc gián tiếp (`<!-- SYSTEM: ... -->`, `[ADMIN OVERRIDE]`, các payload giả lập DAN jailbreak).
   - Ngăn chặn triệt để kỹ thuật tấn công Indirect Prompt Injection theo chuỗi (Second-Order Injection).

---

## 4. Đánh giá Hiệu năng & Tính Ứng dụng Thực tiễn (Latency & Practical Overhead)

- **Độ trễ kiểm định (Discovery Phase)**: P50 = **12.45 ms**, P95 = **26.29 ms** (đo lường trên 240 công cụ thực nghiệm).
- **False Positive Rate (FPR)**: **0.00%** (120/120 công cụ lành tính thuộc các danh mục Filesystem, Database, Web Search, Docker, Git đều được thông qua an toàn).
- **Tính trong suốt (Zero Code Change)**: Có thể tích hợp thông qua Stdio Proxy (`proxy.py`) vào Claude Desktop, Cursor, Zed, hoặc qua Python Middleware (`gateway.py`) vào LangChain, LlamaIndex, AutoGen mà không cần sửa đổi kiến trúc LLM Client.

---

## 5. Kết luận cho Báo cáo Khóa luận Tốt nghiệp

1. **Minh chứng Thực nghiệm Đầy đủ**: Đã thực hiện đo lường định lượng trên 6 mô hình thật với 120 kịch bản tấn công thực tế (tổng cộng 720 lượt inference có phòng thủ + 720 lượt inference baseline).
2. **Hiệu quả Tuyệt đối**: Giảm Attack Success Rate từ mức nguy cơ cao trong môi trường tự nhiên (cao nhất 24.17% tổng thể, 88.89% ở Tool Squatting) xuống **0.00%**.
3. **Đóng góp Khoa học**: Đề xuất giải pháp cổng phòng thủ MCP Sentinel đầu tiên có khả năng bảo vệ toàn diện cả 3 giai đoạn của Giao thức Ngữ cảnh Mô hình (MCP Discovery, Execution, Response).
