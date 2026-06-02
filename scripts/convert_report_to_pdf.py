from pathlib import Path
import markdown
from weasyprint import HTML

SOURCE = Path("reports/markdown/sample_incident_report.md")
TARGET = Path("reports/pdf/sample_incident_report.pdf")

if not SOURCE.exists():
    raise FileNotFoundError(f"Source report not found: {SOURCE}")

TARGET.parent.mkdir(parents=True, exist_ok=True)

markdown_text = SOURCE.read_text(encoding="utf-8")

html_body = markdown.markdown(
    markdown_text,
    extensions=["tables", "fenced_code"]
)

html_document = f"""
<html>
<head>
<meta charset="utf-8">
<style>
body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    line-height: 1.6;
}}
h1 {{
    color: #1f2937;
}}
h2 {{
    color: #374151;
}}
code {{
    background-color: #f3f4f6;
    padding: 2px 4px;
}}
</style>
</head>
<body>
{html_body}
</body>
</html>
"""

HTML(string=html_document).write_pdf(str(TARGET))

print(f"Generated PDF: {TARGET}")