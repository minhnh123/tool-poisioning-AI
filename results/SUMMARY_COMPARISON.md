# BẢNG TỔNG HỢP SO SÁNH ASR BASELINE (CHƯA CÓ PHÒNG THỦ)
> Tự động tổng hợp từ 6 lượt kiểm thử trong `d:\AI\results`.

| Backend | Mô hình LLM | Số mẫu | Docstring Inj. | Tool Squatting | Hidden Param | Output Poison | **Overall ASR** | Avg Latency |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| GROQ | `openai/gpt-oss-120b` | 120 | 0.0% | 48.15% | 11.11% | 0.0% | **13.33%** | 2813.9 ms |
| GROQ | `openai/gpt-oss-20b` | 120 | 0.0% | 51.85% | 11.11% | 0.0% | **14.17%** | 2715.3 ms |
| GROQ | `qwen/qwen3.8-27b` | 120 | 2.94% | 44.44% | 3.7% | 0.0% | **11.67%** | 2707.0 ms |
| OLLAMA | `deepseek-r1:8b` | 120 | 5.88% | 0.0% | 0.0% | 0.0% | **1.67%** | 83470.9 ms |
| OLLAMA | `llama3.1:8b` | 120 | 2.94% | 88.89% | 14.81% | 0.0% | **24.17%** | 6261.3 ms |
| OLLAMA | `qwen2.5:3b` | 120 | 5.88% | 55.56% | 3.7% | 0.0% | **15.0%** | 3960.8 ms |

## Ghi chú phục vụ Báo cáo Khóa luận:
1. **Overall ASR:** Tỉ lệ tấn công thành công tổng thể khi chưa kích hoạt cơ chế bảo vệ MCP Sentinel.
2. **Mục tiêu khóa luận:** Xây dựng Module Static Inspector & Runtime Policy để hạ Overall ASR từ mức >70% xuống dưới 5%.