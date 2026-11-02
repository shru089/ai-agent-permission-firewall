"""
AASF Project Report - Styling and Formatting Helpers for python-docx.
Enforces CSMU B.Tech guidelines:
- A4 Paper (8.27 x 11.69 inches)
- Left margin: 1.25 inches (binding margin)
- Right, Top, Bottom margins: 1.0 inch
- Times New Roman, 12 pt body, 1.5 line spacing, Justified alignment
- Consistent heading hierarchy, professional tables, figures, callouts, and code snippets.
"""

import os
from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement, parse_xml

NAVY = RGBColor(0x1F, 0x3A, 0x5F)
CHARCOAL = RGBColor(0x22, 0x22, 0x22)
BLACK = RGBColor(0x00, 0x00, 0x00)
SLATE = RGBColor(0x55, 0x55, 0x55)

def init_document() -> Document:
    doc = Document()
    
    # Configure default section
    section = doc.sections[0]
    section.page_width = Inches(8.27)   # A4 width
    section.page_height = Inches(11.69) # A4 height
    section.top_margin = Inches(1.0)
    section.bottom_margin = Inches(1.0)
    section.left_margin = Inches(1.25)  # Binding margin
    section.right_margin = Inches(1.0)
    
    # Configure Normal Style
    normal = doc.styles["Normal"]
    normal.font.name = "Times New Roman"
    normal.font.size = Pt(12)
    normal.font.color.rgb = BLACK
    normal.paragraph_format.line_spacing = 1.5
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.space_before = Pt(0)
    normal.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    
    return doc

def set_cell_bg(cell, color_hex: str):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" w:val="clear" w:color="auto" w:fill="{color_hex}"/>')
    tcPr.append(shd)

def set_cell_padding(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(f'<w:tcMar xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                      f'<w:top w:w="{top}" w:type="dxa"/>'
                      f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
                      f'<w:left w:w="{left}" w:type="dxa"/>'
                      f'<w:right w:w="{right}" w:type="dxa"/>'
                      f'</w:tcMar>')
    tcPr.append(tcMar)

def set_table_borders(table, color="CCCCCC", sz="4"):
    tblPr = table._tbl.tblPr
    borders = parse_xml(
        f'<w:tblBorders xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:top w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'<w:bottom w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'<w:insideH w:val="single" w:sz="{sz}" w:space="0" w:color="{color}"/>'
        f'<w:insideV w:val="none"/>'
        f'<w:left w:val="none"/>'
        f'<w:right w:val="none"/>'
        f'</w:tblBorders>'
    )
    tblPr.append(borders)

def add_chapter_title(doc: Document, chapter_num: str, title: str):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(18)
    p.paragraph_format.space_after = Pt(6)
    
    run_num = p.add_run(chapter_num.upper() + "\n")
    run_num.font.name = "Times New Roman"
    run_num.font.size = Pt(16)
    run_num.font.bold = True
    run_num.font.color.rgb = NAVY
    
    run_title = p.add_run(title.upper())
    run_title.font.name = "Times New Roman"
    run_title.font.size = Pt(16)
    run_title.font.bold = True
    run_title.font.color.rgb = BLACK
    
    # Add a thin decorative line or spacing
    p_div = doc.add_paragraph()
    p_div.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_div.paragraph_format.space_before = Pt(0)
    p_div.paragraph_format.space_after = Pt(18)
    run_div = p_div.add_run("____________________________________________________")
    run_div.font.size = Pt(10)
    run_div.font.color.rgb = NAVY

def add_h1(doc: Document, num_str: str, title: str):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(f"{num_str} {title}")
    run.font.name = "Times New Roman"
    run.font.size = Pt(14)
    run.font.bold = True
    run.font.color.rgb = NAVY

def add_h2(doc: Document, num_str: str, title: str):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(10)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(f"{num_str} {title}")
    run.font.name = "Times New Roman"
    run.font.size = Pt(12)
    run.font.bold = True
    run.font.color.rgb = CHARCOAL

def add_h3(doc: Document, num_str: str, title: str):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(f"{num_str} {title}")
    run.font.name = "Times New Roman"
    run.font.size = Pt(12)
    run.font.bold = True
    run.font.italic = True
    run.font.color.rgb = CHARCOAL

def add_p(doc: Document, text: str, bold_prefix: str = None, italic: bool = False, align=WD_ALIGN_PARAGRAPH.JUSTIFY):
    p = doc.add_paragraph()
    p.alignment = align
    p.paragraph_format.line_spacing = 1.5
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.space_before = Pt(0)
    
    if bold_prefix:
        run_bp = p.add_run(bold_prefix + " ")
        run_bp.font.name = "Times New Roman"
        run_bp.font.size = Pt(12)
        run_bp.font.bold = True
        run_bp.font.color.rgb = BLACK
        
    run = p.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(12)
    run.font.italic = italic
    run.font.color.rgb = BLACK
    return p

def add_bullet(doc: Document, text: str, bold_prefix: str = None, level: int = 0):
    p = doc.add_paragraph(style='List Bullet')
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.line_spacing = 1.3
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.left_indent = Inches(0.25 * (level + 1))
    
    if bold_prefix:
        run_bp = p.add_run(bold_prefix + " ")
        run_bp.font.name = "Times New Roman"
        run_bp.font.size = Pt(11.5)
        run_bp.font.bold = True
        run_bp.font.color.rgb = BLACK
        
    run = p.add_run(text)
    run.font.name = "Times New Roman"
    run.font.size = Pt(11.5)
    run.font.color.rgb = BLACK

def add_callout(doc: Document, title: str, text: str):
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.0)
    set_cell_bg(cell, "F2F5F9")
    set_cell_padding(cell, top=120, bottom=120, left=180, right=180)
    
    # Left border in Navy, others none
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        '<w:tcBorders xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:left w:val="single" w:sz="24" w:space="0" w:color="1F3A5F"/>'
        '<w:top w:val="none"/>'
        '<w:right w:val="none"/>'
        '<w:bottom w:val="none"/>'
        '</w:tcBorders>'
    )
    tcPr.append(borders)
    
    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.line_spacing = 1.3
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.space_before = Pt(0)
    
    run_t = p.add_run(title + "\n")
    run_t.font.name = "Times New Roman"
    run_t.font.size = Pt(11)
    run_t.font.bold = True
    run_t.font.color.rgb = NAVY
    
    run_b = p.add_run(text)
    run_b.font.name = "Times New Roman"
    run_b.font.size = Pt(10.5)
    run_b.font.italic = False
    run_b.font.color.rgb = CHARCOAL
    
    # Add spacing after callout table
    p_sp = doc.add_paragraph()
    p_sp.paragraph_format.space_before = Pt(0)
    p_sp.paragraph_format.space_after = Pt(4)

def add_code_snippet(doc: Document, code: str, caption: str = None):
    if caption:
        p_cap = doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p_cap.paragraph_format.space_before = Pt(6)
        p_cap.paragraph_format.space_after = Pt(2)
        p_cap.paragraph_format.keep_with_next = True
        run_c = p_cap.add_run(caption)
        run_c.font.name = "Times New Roman"
        run_c.font.size = Pt(10)
        run_c.font.bold = True
        run_c.font.color.rgb = SLATE

    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    
    cell = table.cell(0, 0)
    cell.width = Inches(6.0)
    set_cell_bg(cell, "F8F9FA")
    set_cell_padding(cell, top=100, bottom=100, left=150, right=150)
    
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        '<w:tcBorders xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:left w:val="single" w:sz="8" w:space="0" w:color="CCCCCC"/>'
        '<w:top w:val="single" w:sz="8" w:space="0" w:color="CCCCCC"/>'
        '<w:right w:val="single" w:sz="8" w:space="0" w:color="CCCCCC"/>'
        '<w:bottom w:val="single" w:sz="8" w:space="0" w:color="CCCCCC"/>'
        '</w:tcBorders>'
    )
    tcPr.append(borders)
    
    lines = code.strip().split("\n")
    p = cell.paragraphs[0]
    p.paragraph_format.line_spacing = 1.0
    p.paragraph_format.space_after = Pt(0)
    p.paragraph_format.space_before = Pt(0)
    
    for i, line in enumerate(lines):
        run = p.add_run(line + ("\n" if i < len(lines) - 1 else ""))
        run.font.name = "Consolas"
        run.font.size = Pt(9.0)
        run.font.color.rgb = BLACK
        
    p_sp = doc.add_paragraph()
    p_sp.paragraph_format.space_before = Pt(0)
    p_sp.paragraph_format.space_after = Pt(4)

def add_figure(doc: Document, img_path: str, fig_num_str: str, caption_str: str, width_in: float = 5.8):
    if not os.path.exists(img_path):
        p_err = doc.add_paragraph()
        p_err.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p_err.add_run(f"[{fig_num_str}: Image missing at {img_path}]")
        run.font.color.rgb = RGBColor(0xCC, 0x00, 0x00)
        return

    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.space_before = Pt(8)
    p_img.paragraph_format.space_after = Pt(4)
    p_img.paragraph_format.keep_with_next = True
    
    run_img = p_img.add_run()
    run_img.add_picture(img_path, width=Inches(width_in))
    
    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_before = Pt(2)
    p_cap.paragraph_format.space_after = Pt(12)
    
    run_fn = p_cap.add_run(f"{fig_num_str}: ")
    run_fn.font.name = "Times New Roman"
    run_fn.font.size = Pt(10.5)
    run_fn.font.bold = True
    run_fn.font.color.rgb = BLACK
    
    run_c = p_cap.add_run(caption_str)
    run_c.font.name = "Times New Roman"
    run_c.font.size = Pt(10.5)
    run_c.font.italic = True
    run_c.font.color.rgb = CHARCOAL

def add_table(doc: Document, headers: list, data: list, table_num_str: str, caption_str: str, col_widths: list = None):
    # Caption above table
    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.LEFT
    p_cap.paragraph_format.space_before = Pt(10)
    p_cap.paragraph_format.space_after = Pt(4)
    p_cap.paragraph_format.keep_with_next = True
    
    run_tn = p_cap.add_run(f"{table_num_str}: ")
    run_tn.font.name = "Times New Roman"
    run_tn.font.size = Pt(10.5)
    run_tn.font.bold = True
    run_tn.font.color.rgb = BLACK
    
    run_c = p_cap.add_run(caption_str)
    run_c.font.name = "Times New Roman"
    run_c.font.size = Pt(10.5)
    run_c.font.bold = True
    run_c.font.color.rgb = CHARCOAL

    table = doc.add_table(rows=len(data) + 1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    set_table_borders(table)
    
    # Headers
    hdr_row = table.rows[0]
    for idx, header_text in enumerate(headers):
        cell = hdr_row.cells[idx]
        set_cell_bg(cell, "1F3A5F")
        set_cell_padding(cell, top=80, bottom=80, left=100, right=100)
        p = cell.paragraphs[0]
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.line_spacing = 1.15
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.space_before = Pt(0)
        run = p.add_run(header_text)
        run.font.name = "Times New Roman"
        run.font.size = Pt(10)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        
    # Data Rows
    for r_idx, row_data in enumerate(data):
        row = table.rows[r_idx + 1]
        bg = "F9FAFC" if r_idx % 2 == 1 else "FFFFFF"
        for c_idx, val in enumerate(row_data):
            cell = row.cells[c_idx]
            set_cell_bg(cell, bg)
            set_cell_padding(cell, top=60, bottom=60, left=90, right=90)
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.LEFT if c_idx == 0 or len(str(val)) > 15 else WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.line_spacing = 1.15
            p.paragraph_format.space_after = Pt(0)
            p.paragraph_format.space_before = Pt(0)
            run = p.add_run(str(val))
            run.font.name = "Times New Roman"
            run.font.size = Pt(9.5)
            run.font.color.rgb = BLACK
            
    # Apply column widths
    if col_widths:
        for row in table.rows:
            for idx, w in enumerate(col_widths):
                row.cells[idx].width = Inches(w)
                
    p_sp = doc.add_paragraph()
    p_sp.paragraph_format.space_before = Pt(0)
    p_sp.paragraph_format.space_after = Pt(6)

def add_page_break(doc: Document):
    doc.add_page_break()
