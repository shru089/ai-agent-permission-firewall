"""
Master Document Builder for AASF B.Tech Final Year Project Report.
Assembles all Front Matter, Chapters 1-9, References, and Appendices I-V,
saves AASF_Final_Project_Report.docx, and automates Word COM PDF export.
"""

import os
import sys
import time

# Ensure report_builder modules are importable
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from styles import init_document
from front_matter import add_front_matter
from chapter1 import add_chapter1
from chapter2 import add_chapter2
from chapter3 import add_chapter3
from chapter4 import add_chapter4
from chapter5 import add_chapter5
from chapter6 import add_chapter6
from chapter7 import add_chapter7
from chapter8 import add_chapter8
from chapter9_and_backmatter import add_chapter9, add_back_matter

def build_report():
    print("=" * 80)
    print("AASF B.TECH PROJECT REPORT - COMPREHENSIVE GENERATION PIPELINE")
    print("=" * 80)
    
    start_time = time.time()
    doc = init_document()
    
    print("[1/11] Generating Front Matter (Cover, Certificate, Abstract, TOC, Lists)...")
    add_front_matter(doc)
    
    print("[2/11] Generating Chapter 1: Introduction...")
    add_chapter1(doc)
    
    print("[3/11] Generating Chapter 2: Literature Review...")
    add_chapter2(doc)
    
    print("[4/11] Generating Chapter 3: System Requirement Specification (SRS)...")
    add_chapter3(doc)
    
    print("[5/11] Generating Chapter 4: Plan of Project...")
    add_chapter4(doc)
    
    print("[6/11] Generating Chapter 5: Project Analysis...")
    add_chapter5(doc)
    
    print("[7/11] Generating Chapter 6: Project Design...")
    add_chapter6(doc)
    
    print("[8/11] Generating Chapter 7: Implementation...")
    add_chapter7(doc)
    
    print("[9/11] Generating Chapter 8: Result Analysis and Discussion...")
    add_chapter8(doc)
    
    print("[10/11] Generating Chapter 9: Conclusion and Future Scope...")
    add_chapter9(doc)
    
    print("[11/11] Generating Back Matter (References & Appendices I–V)...")
    add_back_matter(doc)
    
    # Save target paths
    output_dir = os.path.abspath("AASF_FINAL_PROJECT_REPORT")
    os.makedirs(output_dir, exist_ok=True)
    docx_path = os.path.join(output_dir, "AASF_Final_Project_Report.docx")
    pdf_path = os.path.join(output_dir, "AASF_Final_Project_Report.pdf")
    
    print(f"\nSaving Word Document to: {docx_path}")
    doc.save(docx_path)
    file_size_kb = os.path.getsize(docx_path) / 1024.0
    print(f" -> Word Document generated successfully! Size: {file_size_kb:.2f} KB")
    
    # Export to PDF via Word COM Automation
    print("\nExporting to PDF via Microsoft Word COM Automation...")
    try:
        import win32com.client
        word = win32com.client.Dispatch("Word.Application")
        word.Visible = False
        
        doc_com = word.Documents.Open(docx_path)
        # Update Table of Contents and Fields
        try:
            for table_of_contents in doc_com.TablesOfContents:
                table_of_contents.Update()
            doc_com.Fields.Update()
        except Exception as e_field:
            print(f" (Note: Field update notification: {e_field})")
            
        # 17 = wdFormatPDF
        doc_com.SaveAs(pdf_path, FileFormat=17)
        doc_com.Close()
        word.Quit()
        pdf_size_kb = os.path.getsize(pdf_path) / 1024.0
        print(f" -> PDF Document generated successfully! Size: {pdf_size_kb:.2f} KB")
        print(f" -> PDF Path: {pdf_path}")
    except Exception as e:
        print(f" [WARNING] Word COM Automation encounter: {e}")
        print(" Word document remains intact and valid.")
        
    elapsed = time.time() - start_time
    print("=" * 80)
    print(f"REPORT GENERATION COMPLETED IN {elapsed:.2f} SECONDS")
    print("=" * 80)

if __name__ == "__main__":
    build_report()
