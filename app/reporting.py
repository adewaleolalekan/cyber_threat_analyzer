# reporting.py
from fpdf import FPDF
from datetime import datetime
import os

# Define colors for different threat levels for better visual scanning
THREAT_COLORS = {
    "high": (255, 224, 224),    # Light Red
    "medium": (255, 236, 204), # Light Orange
    "low": (224, 242, 224),     # Light Green
    "unknown": (242, 242, 242)  # Light Grey
}

def generate_report(filename, user_ip, enrichments, gpt_output, format_options=None):
    """
    Generates a neatly formatted PDF report with tables and color-coding,
    with manual page break handling and safe character encoding.
    """
    if format_options is None:
        format_options = {}

    font = format_options.get("font", "Arial")
    font_size = 11
    line_height = 7
    margin = 15

    pdf = FPDF()
    pdf.set_margins(margin, margin, margin)
    pdf.set_auto_page_break(auto=True, margin=margin)
    pdf.add_page()

    # --- Helper function to draw the table header ---
    def draw_table_header():
        pdf.set_font(font, 'B', font_size)
        pdf.set_fill_color(230, 230, 230)
        col_widths = {"type": 30, "indicator": 100, "score": 25, "level": 25}
        pdf.cell(col_widths["type"], line_height, "Type", border=1, align='C', fill=True)
        pdf.cell(col_widths["indicator"], line_height, "Indicator", border=1, align='C', fill=True)
        pdf.cell(col_widths["score"], line_height, "Score", border=1, align='C', fill=True)
        pdf.cell(col_widths["level"], line_height, "Level", border=1, align='C', fill=True)
        pdf.ln()

    # --- Report Header ---
    pdf.set_font(font, "B", 20)
    pdf.cell(0, 10, "Cyber Threat Analysis Report", ln=True, align="C")
    pdf.ln(10)

    # --- Analysis Metadata ---
    pdf.set_font(font, "B", 14)
    pdf.cell(0, line_height, "Analysis Overview")
    pdf.ln(line_height + 1)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 180, pdf.get_y())
    pdf.ln(4)

    pdf.set_font(font, "", font_size)
    meta_info = {
        "File Analyzed": os.path.basename(filename),
        "Analysis Date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "Requesting IP": user_ip
    }
    for key, value in meta_info.items():
        # Encode strings to latin-1, replacing unsupported characters.
        safe_value = value.encode('latin-1', 'replace').decode('latin-1')
        pdf.set_font(font, "B", font_size)
        pdf.cell(40, line_height, f"{key}:")
        pdf.set_font(font, "", font_size)
        pdf.cell(0, line_height, safe_value, ln=True)
    pdf.ln(8)

    # --- AI Executive Summary ---
    if gpt_output:
        pdf.set_font(font, "B", 14)
        pdf.cell(0, line_height, "Executive Summary (AI Analysis)")
        pdf.ln(line_height + 1)
        pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 180, pdf.get_y())
        pdf.ln(4)

        pdf.set_font(font, "", font_size)
        for line in gpt_output.splitlines():
            # Check if a page break is needed before drawing the line
            if pdf.get_y() + (line_height * 2) > pdf.page_break_trigger:
                pdf.add_page()
            
            # Sanitize the line to prevent encoding errors
            safe_line = line.encode('latin-1', 'replace').decode('latin-1')

            if safe_line.strip().startswith(("* ", "- ")):
                pdf.ln(2)
                pdf.cell(5)
                # Use a simple hyphen instead of a unicode bullet
                pdf.multi_cell(0, line_height, f"- {safe_line.strip()[2:]}")
            elif safe_line.strip().endswith(":") and len(safe_line) < 80:
                pdf.ln(4)
                pdf.set_font(font, "B", font_size)
                pdf.cell(0, line_height, safe_line, ln=True)
                pdf.set_font(font, "", font_size)
            elif safe_line:
                pdf.multi_cell(0, line_height, safe_line)
        pdf.ln(8)

    # --- Threat Indicators Section ---
    pdf.set_font(font, "B", 14)
    pdf.cell(0, line_height, "Threat Indicators Found")
    pdf.ln(line_height + 1)
    pdf.line(pdf.get_x(), pdf.get_y(), pdf.get_x() + 180, pdf.get_y())
    pdf.ln(4)

    if enrichments:
        draw_table_header()
        col_widths = {"type": 30, "indicator": 100, "score": 25, "level": 25}

        levels = {"high": [], "medium": [], "low": [], "unknown": []}
        for item in enrichments:
            levels[item.get("level", "unknown").lower()].append(item)

        pdf.set_font(font, '', font_size - 1)
        for level_name in ["high", "medium", "low", "unknown"]:
            if levels[level_name]:
                r, g, b = THREAT_COLORS[level_name]
                pdf.set_fill_color(r, g, b)
                for item in levels[level_name]:
                    if pdf.get_y() + line_height > pdf.page_break_trigger:
                        pdf.add_page()
                        draw_table_header()
                        pdf.set_font(font, '', font_size - 1)

                    # Sanitize each piece of data before adding it to the cell
                    cell_type = str(item.get("type", "N/A")).capitalize().encode('latin-1', 'replace').decode('latin-1')
                    cell_indicator = str(item.get("indicator", "N/A")).encode('latin-1', 'replace').decode('latin-1')
                    cell_score = str(item.get("score", "N/A")).encode('latin-1', 'replace').decode('latin-1')
                    cell_level = str(item.get("level", "N/A")).capitalize().encode('latin-1', 'replace').decode('latin-1')

                    pdf.cell(col_widths["type"], line_height, cell_type, border='LR', align='C', fill=True)
                    pdf.cell(col_widths["indicator"], line_height, cell_indicator, border='LR', fill=True)
                    pdf.cell(col_widths["score"], line_height, cell_score, border='LR', align='C', fill=True)
                    pdf.cell(col_widths["level"], line_height, cell_level, border='LR', align='C', fill=True)
                    pdf.ln()
        
        pdf.cell(sum(col_widths.values()), 0, '', 'T')
    else:
        pdf.set_font(font, '', font_size)
        pdf.cell(0, 10, "No threat indicators were extracted from the file.", ln=True)
    pdf.ln(10)

    # --- Footer ---
    pdf.set_y(-15)
    pdf.set_font(font, "I", 8)
    pdf.set_text_color(128, 128, 128)
    pdf.cell(0, 10, f"Page {pdf.page_no()}", 0, 0, "C")

    out_path = f"/tmp/{os.path.basename(filename).replace('.', '_')}_report.pdf"
    pdf.output(out_path)
    return out_path

