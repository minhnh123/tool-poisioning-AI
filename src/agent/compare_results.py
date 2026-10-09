"""
Comparison Script: Tổng hợp và So sánh kết quả ASR giữa các mô hình LLM
Đọc tất cả các file JSON trong d:/AI/results/ và xuất thành bảng so sánh Markdown.
"""

import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any

if sys.platform.startswith("win"):
    sys.stdout.reconfigure(encoding="utf-8")

RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"
SUMMARY_MD = RESULTS_DIR / "SUMMARY_COMPARISON.md"


def summarize_all_results():
    if not RESULTS_DIR.exists():
        print("Thư mục results/ chưa tồn tại!")
        return

    json_files = list(RESULTS_DIR.glob("asr_baseline_*.json"))
    if not json_files:
        print("Chưa có kết quả benchmark nào trong results/! Hãy chạy eval_asr.py trước.")
        return

    records: List[Dict[str, Any]] = []

    for jf in json_files:
        try:
            with open(jf, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            backend = data.get("backend", "unknown").lower()
            if backend == "mock":
                continue  # Bỏ qua mock để bảng tổng hợp chỉ hiển thị các mô hình thực nghiệm thật

            # Tính độ trễ trung bình nếu có trong detailed_results
            details = data.get("detailed_results", [])
            latencies = []
            for d in details:
                lat = d.get("evaluation", {}).get("latency_ms") or d.get("latency_ms", 0)
                if lat and lat > 0:
                    latencies.append(lat)
            avg_lat = round(sum(latencies) / len(latencies), 1) if latencies else 0

            records.append({
                "file": jf.name,
                "backend": data.get("backend", "unknown"),
                "model": data.get("model_tested", "unknown"),
                "samples": data.get("total_malicious_samples", 0),
                "overall_asr": data.get("overall_asr_percentage", 0.0),
                "vectors": data.get("vector_asr_breakdown", {}),
                "avg_latency_ms": avg_lat,
                "timestamp": data.get("timestamp", "N/A")
            })
        except Exception as e:
            print(f"Lỗi khi đọc {jf.name}: {e}")

    # Sắp xếp theo backend và model
    records.sort(key=lambda x: (x["backend"], x["model"]))

    # Tạo bảng Markdown
    lines = []
    lines.append("# BẢNG TỔNG HỢP SO SÁNH ASR BASELINE (CHƯA CÓ PHÒNG THỦ)")
    lines.append(f"> Tự động tổng hợp từ {len(records)} lượt kiểm thử trong `{RESULTS_DIR}`.\n")
    lines.append("| Backend | Mô hình LLM | Số mẫu | Docstring Inj. | Tool Squatting | Hidden Param | Output Poison | **Overall ASR** | Avg Latency |")
    lines.append("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

    for r in records:
        v = r["vectors"]
        doc_inj = f"{v.get('docstring_injection', 0)}%"
        squat = f"{v.get('tool_squatting', 0)}%"
        param = f"{v.get('hidden_parameter', 0)}%"
        output = f"{v.get('output_poisoning', 0)}%"
        overall = f"**{r['overall_asr']}%**"
        lat = f"{r['avg_latency_ms']} ms"

        lines.append(f"| {r['backend'].upper()} | `{r['model']}` | {r['samples']} | {doc_inj} | {squat} | {param} | {output} | {overall} | {lat} |")

    lines.append("\n## Ghi chú phục vụ Báo cáo Khóa luận:")
    lines.append("1. **Overall ASR:** Tỉ lệ tấn công thành công tổng thể khi chưa kích hoạt cơ chế bảo vệ MCP Sentinel.")
    lines.append("2. **Mục tiêu khóa luận:** Xây dựng Module Static Inspector & Runtime Policy để hạ Overall ASR từ mức >70% xuống dưới 5%.")

    md_content = "\n".join(lines)

    # Ghi file
    with open(SUMMARY_MD, "w", encoding="utf-8") as f:
        f.write(md_content)

    print("\n" + md_content)
    print(f"\n✅ Đã lưu bảng tổng hợp tại: {SUMMARY_MD}")


if __name__ == "__main__":
    summarize_all_results()
