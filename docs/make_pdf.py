"""Exports docs/WRITEUP.md to docs/WRITEUP.pdf with reportlab (small Markdown subset only)."""

import re
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer

here = Path(__file__).parent
styles = getSampleStyleSheet()
body = ParagraphStyle("b", parent=styles["BodyText"], fontSize=9.6, leading=12.2, spaceAfter=3)
h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=13, spaceAfter=2, spaceBefore=0)
h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=10, spaceBefore=5, spaceAfter=2)


def inline(text):
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    return re.sub(r"`(.+?)`", r"<font face='Courier'>\1</font>", text)


story, bullets = [], []


def flush():
    if bullets:
        story.append(ListFlowable([ListItem(Paragraph(inline(b), body), leftIndent=10) for b in bullets],
                                  bulletType="bullet", start="\u2022", leftIndent=10))
        bullets.clear()


for line in (here / "WRITEUP.md").read_text().splitlines():
    if line.startswith("- "):
        bullets.append(line[2:])
        continue
    flush()
    if line.startswith("# "):
        story.append(Paragraph(inline(line[2:]), h1))
    elif line.startswith("## "):
        story.append(Paragraph(inline(line[3:]), h2))
    elif line.strip():
        story.append(Paragraph(inline(line), body))
flush()

doc = SimpleDocTemplate(str(here / "WRITEUP.pdf"), pagesize=A4, leftMargin=1.6 * cm, rightMargin=1.6 * cm,
                        topMargin=1.3 * cm, bottomMargin=1.2 * cm)
doc.build(story)
print("wrote", here / "WRITEUP.pdf")
