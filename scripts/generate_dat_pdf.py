#!/usr/bin/env python3
"""Générateur autonome de PDF pour le Dossier d'Architecture Technique (DAT).

Génère un document PDF 1.4 multipage complet, stylisé et professionnel,
sans aucune dépendance tierce (bibliothèque standard Python 3 uniquement).
"""

from __future__ import annotations

import re
import sys
import zlib
from pathlib import Path
from typing import List, Tuple

PAGE_WIDTH = 595.28  # A4 pt
PAGE_HEIGHT = 841.89  # A4 pt
MARGIN_LEFT = 50.0
MARGIN_RIGHT = 50.0
MARGIN_TOP = 55.0
MARGIN_BOTTOM = 55.0
USABLE_WIDTH = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT
USABLE_HEIGHT = PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM


def escape_pdf_string(s: str) -> str:
    """Échappe les caractères réservés PDF et convertit en ISO-8859-1."""
    # Remplacer les caractères Unicode fréquents non Latin-1 par équivalents
    replacements = {
        "’": "'",
        "‘": "'",
        "“": '"',
        "”": '"',
        "—": "-",
        "–": "-",
        "…": "...",
        "•": "*",
        "→": "->",
        "←": "<-",
        "⇒": "=>",
        "≥": ">=",
        "≤": "<=",
        "≠": "!=",
        "±": "+/-",
        "°": " deg ",
        "²": "2",
        "³": "3",
        "🛡": "",
        "🏭": "",
        "🎯": "",
        "🏛": "",
        "🧩": "",
        "🔒": "",
        "💻": "",
        "☁": "",
        "📊": "",
        "🏁": "",
        "📐": "",
        "⚙": "",
        "✅": "[OK]",
        "❌": "[KO]",
    }
    for k, v in replacements.items():
        s = s.replace(k, v)

    # Encoder en latin-1 avec remplacement sécurisé
    latin_text = s.encode("latin-1", "replace").decode("latin-1")
    res = []
    for char in latin_text:
        if char == "\\":
            res.append("\\\\")
        elif char == "(":
            res.append("\\(")
        elif char == ")":
            res.append("\\)")
        elif ord(char) < 32 or ord(char) > 126:
            res.append(f"\\{ord(char):03o}")
        else:
            res.append(char)
    return "".join(res)


class SimplePDFWriter:
    def __init__(self, title: str = "Dossier d'Architecture Technique"):
        self.title = title
        self.objects: List[bytes] = []
        self.pages: List[Tuple[int, bytes]] = []  # (contents_obj_id, stream_bytes)
        self.current_page_commands: List[str] = []
        self.current_y = PAGE_HEIGHT - MARGIN_TOP
        self.page_number = 0

    def _add_object(self, data: bytes) -> int:
        self.objects.append(data)
        return len(self.objects)  # 1-based index

    def new_page(self) -> None:
        if self.page_number > 0:
            self._finalize_page()
        self.page_number += 1
        self.current_page_commands = []
        self.current_y = PAGE_HEIGHT - MARGIN_TOP

        # En-tête de page (sauf première page)
        if self.page_number > 1:
            # Ligne de séparation d'en-tête
            self.current_page_commands.append("0.75 0.75 0.75 RG 0.5 w")
            self.current_page_commands.append(
                f"{MARGIN_LEFT} {PAGE_HEIGHT - 38} m {PAGE_WIDTH - MARGIN_RIGHT} {PAGE_HEIGHT - 38} l S"
            )
            # Texte d'en-tête
            self.current_page_commands.append(
                f"BT /F1 8 Tf 0.4 0.4 0.4 rg {MARGIN_LEFT} {PAGE_HEIGHT - 32} Td ({escape_pdf_string(self.title)}) Tj ET"
            )
            self.current_page_commands.append(
                f"BT /F1 8 Tf 0.4 0.4 0.4 rg {PAGE_WIDTH - MARGIN_RIGHT - 110} {PAGE_HEIGHT - 32} Td (SecuriGlass Factory OS) Tj ET"
            )

    def _finalize_page(self) -> None:
        # Pied de page
        self.current_page_commands.append("0.75 0.75 0.75 RG 0.5 w")
        self.current_page_commands.append(
            f"{MARGIN_LEFT} {MARGIN_BOTTOM + 15} m {PAGE_WIDTH - MARGIN_RIGHT} {MARGIN_BOTTOM + 15} l S"
        )
        page_str = f"Page {self.page_number}"
        self.current_page_commands.append(
            f"BT /F1 8 Tf 0.4 0.4 0.4 rg {MARGIN_LEFT} {MARGIN_BOTTOM + 5} Td (Diffusion Restreinte - Homologation EBIOS RM / IEC 62443) Tj ET"
        )
        self.current_page_commands.append(
            f"BT /F2 8 Tf 0.2 0.2 0.2 rg {PAGE_WIDTH - MARGIN_RIGHT - 40} {MARGIN_BOTTOM + 5} Td ({escape_pdf_string(page_str)}) Tj ET"
        )

        stream_data = "\n".join(self.current_page_commands).encode("latin-1")
        compressed = zlib.compress(stream_data)
        obj_content = (
            f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode(
                "ascii"
            )
            + compressed
            + b"\nendstream"
        )
        contents_id = self._add_object(obj_content)
        self.pages.append((contents_id, obj_content))

    def ensure_space(self, height_needed: float) -> None:
        if self.current_y - height_needed < MARGIN_BOTTOM + 25:
            self.new_page()

    def add_title(self, text: str) -> None:
        self.ensure_space(60)
        self.current_page_commands.append("0.1 0.2 0.4 rg")
        # Bannière bleue
        self.current_page_commands.append(
            f"0.08 0.2 0.38 rg {MARGIN_LEFT} {self.current_y - 32} {USABLE_WIDTH} 36 re f"
        )
        self.current_page_commands.append(
            f"BT /F2 16 Tf 1.0 1.0 1.0 rg {MARGIN_LEFT + 10} {self.current_y - 22} Td ({escape_pdf_string(text)}) Tj ET"
        )
        self.current_y -= 48

    def add_h1(self, text: str) -> None:
        self.ensure_space(45)
        self.current_y -= 12
        # Bandeau de section
        self.current_page_commands.append(
            f"0.92 0.94 0.98 rg {MARGIN_LEFT} {self.current_y - 20} {USABLE_WIDTH} 22 re f"
        )
        self.current_page_commands.append("0.1 0.25 0.5 RG 2 w")
        self.current_page_commands.append(
            f"{MARGIN_LEFT} {self.current_y - 20} m {MARGIN_LEFT} {self.current_y + 2} l S"
        )
        self.current_page_commands.append(
            f"BT /F2 12 Tf 0.1 0.2 0.45 rg {MARGIN_LEFT + 8} {self.current_y - 14} Td ({escape_pdf_string(text)}) Tj ET"
        )
        self.current_y -= 30

    def add_h2(self, text: str) -> None:
        self.ensure_space(32)
        self.current_y -= 8
        self.current_page_commands.append(
            f"BT /F2 10.5 Tf 0.15 0.3 0.5 rg {MARGIN_LEFT} {self.current_y - 10} Td ({escape_pdf_string(text)}) Tj ET"
        )
        self.current_page_commands.append("0.8 0.85 0.9 RG 0.75 w")
        self.current_page_commands.append(
            f"{MARGIN_LEFT} {self.current_y - 13} m {MARGIN_LEFT + 220} {self.current_y - 13} l S"
        )
        self.current_y -= 22

    def add_paragraph(self, text: str) -> None:
        # Wrap simple à ~95 caractères
        words = text.split(" ")
        lines = []
        current_line = []
        current_len = 0
        for w in words:
            if current_len + len(w) + 1 > 92:
                lines.append(" ".join(current_line))
                current_line = [w]
                current_len = len(w)
            else:
                current_line.append(w)
                current_len += len(w) + 1
        if current_line:
            lines.append(" ".join(current_line))

        for line in lines:
            self.ensure_space(14)
            self.current_page_commands.append(
                f"BT /F1 9 Tf 0.15 0.15 0.15 rg {MARGIN_LEFT} {self.current_y - 8} Td ({escape_pdf_string(line)}) Tj ET"
            )
            self.current_y -= 12
        self.current_y -= 4

    def add_bullet(self, text: str) -> None:
        self.ensure_space(15)
        # Puce
        self.current_page_commands.append(
            f"0.1 0.4 0.7 rg {MARGIN_LEFT + 3} {self.current_y - 6} 3 3 re f"
        )
        words = text.split(" ")
        lines = []
        current_line = []
        current_len = 0
        for w in words:
            if current_len + len(w) + 1 > 86:
                lines.append(" ".join(current_line))
                current_line = [w]
                current_len = len(w)
            else:
                current_line.append(w)
                current_len += len(w) + 1
        if current_line:
            lines.append(" ".join(current_line))

        for i, line in enumerate(lines):
            self.ensure_space(13)
            indent = MARGIN_LEFT + 12
            self.current_page_commands.append(
                f"BT /F1 8.5 Tf 0.2 0.2 0.2 rg {indent} {self.current_y - 7} Td ({escape_pdf_string(line)}) Tj ET"
            )
            self.current_y -= 11.5
        self.current_y -= 2

    def add_code_block(self, lines: List[str]) -> None:
        block_height = len(lines) * 11 + 10
        self.ensure_space(min(block_height, 120))
        # Fond gris clair
        actual_h = len(lines) * 11 + 8
        self.current_page_commands.append(
            f"0.96 0.96 0.97 rg {MARGIN_LEFT} {self.current_y - actual_h} {USABLE_WIDTH} {actual_h} re f"
        )
        self.current_page_commands.append("0.85 0.85 0.88 RG 0.5 w")
        self.current_page_commands.append(
            f"{MARGIN_LEFT} {self.current_y - actual_h} {USABLE_WIDTH} {actual_h} re S"
        )
        self.current_y -= 6

        for line in lines:
            self.ensure_space(12)
            self.current_page_commands.append(
                f"BT /F3 7.5 Tf 0.1 0.1 0.25 rg {MARGIN_LEFT + 8} {self.current_y - 6} Td ({escape_pdf_string(line[:100])}) Tj ET"
            )
            self.current_y -= 11
        self.current_y -= 8

    def add_table_row(
        self,
        cols: List[str],
        col_widths: List[float],
        is_header: bool = False,
    ) -> None:
        self.ensure_space(18)
        bg = "0.90 0.92 0.96" if is_header else "0.98 0.98 0.99"
        font = "/F2" if is_header else "/F1"
        font_size = "8" if is_header else "7.5"
        txt_color = "0.1 0.15 0.3" if is_header else "0.15 0.15 0.15"

        self.current_page_commands.append(
            f"{bg} rg {MARGIN_LEFT} {self.current_y - 14} {USABLE_WIDTH} 15 re f"
        )
        self.current_page_commands.append("0.82 0.84 0.88 RG 0.5 w")
        self.current_page_commands.append(
            f"{MARGIN_LEFT} {self.current_y - 14} {USABLE_WIDTH} 15 re S"
        )

        x = MARGIN_LEFT + 4
        for col_text, w in zip(cols, col_widths):
            clipped = col_text[: int(w / 4.8)]
            self.current_page_commands.append(
                f"BT {font} {font_size} Tf {txt_color} rg {x} {self.current_y - 10} Td ({escape_pdf_string(clipped)}) Tj ET"
            )
            x += w
        self.current_y -= 16

    def compile(self) -> bytes:
        if self.current_page_commands:
            self._finalize_page()

        # Objets de polices
        font_helvetica = self._add_object(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        )
        font_bold = self._add_object(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
        )
        font_courier = self._add_object(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"
        )

        resources_obj = self._add_object(
            f"<< /Font << /F1 {font_helvetica} 0 R /F2 {font_bold} 0 R /F3 {font_courier} 0 R >> >>".encode(
                "ascii"
            )
        )

        # Pages array
        page_obj_ids = []
        for contents_id, _ in self.pages:
            page_obj = self._add_object(
                f"<< /Type /Page /Parent 0 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] /Resources {resources_obj} 0 R /Contents {contents_id} 0 R >>".encode(
                    "ascii"
                )
            )
            page_obj_ids.append(page_obj)

        # Pages root object
        kids_str = " ".join([f"{pid} 0 R" for pid in page_obj_ids])
        pages_root = self._add_object(
            f"<< /Type /Pages /Kids [{kids_str}] /Count {len(page_obj_ids)} >>".encode(
                "ascii"
            )
        )

        # Catalog
        catalog = self._add_object(
            f"<< /Type /Catalog /Pages {pages_root} 0 R >>".encode("ascii")
        )

        # Mettre à jour le Parent dans chaque page
        for pid in page_obj_ids:
            old_data = self.objects[pid - 1]
            updated = old_data.replace(
                b"/Parent 0 0 R", f"/Parent {pages_root} 0 R".encode("ascii")
            )
            self.objects[pid - 1] = updated

        # Écriture du fichier avec table XREF
        output = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
        xref_offsets = [0]

        for i, obj_data in enumerate(self.objects, start=1):
            offset = sum(len(chunk) for chunk in output)
            xref_offsets.append(offset)
            output.append(f"{i} 0 obj\n".encode("ascii") + obj_data + b"\nendobj\n")

        startxref = sum(len(chunk) for chunk in output)
        output.append(f"xref\n0 {len(self.objects) + 1}\n".encode("ascii"))
        output.append(b"0000000000 65535 f \n")
        for offset in xref_offsets[1:]:
            output.append(f"{offset:010d} 00000 n \n".encode("ascii"))

        trailer = (
            f"trailer\n<< /Size {len(self.objects) + 1} /Root {catalog} 0 R >>\n"
            f"startxref\n{startxref}\n%%EOF\n"
        )
        output.append(trailer.encode("ascii"))

        return b"".join(output)


def convert_dat_markdown_to_pdf(md_path: Path, pdf_path: Path) -> None:
    content = md_path.read_text(encoding="utf-8")
    writer = SimplePDFWriter(
        title="SecuriGlass Factory OS - Dossier d'Architecture Technique (DAT)"
    )
    writer.new_page()

    lines = content.splitlines()
    in_code_block = False
    code_lines = []
    in_table = False
    table_headers = []

    for raw_line in lines:
        line = raw_line.strip()

        # Bloc de code
        if line.startswith("```"):
            if in_code_block:
                in_code_block = False
                writer.add_code_block(code_lines)
                code_lines = []
            else:
                in_code_block = True
                code_lines = []
            continue

        if in_code_block:
            code_lines.append(raw_line)
            continue

        # Ligne de séparation ou vide
        if not line or line.startswith("---") or line.startswith("==="):
            in_table = False
            continue

        # Titres
        if line.startswith("# "):
            writer.add_title(line[2:].strip())
        elif line.startswith("## "):
            writer.add_h1(line[3:].strip())
        elif line.startswith("### "):
            writer.add_h2(line[4:].strip())
        elif line.startswith("* ") or line.startswith("- "):
            in_table = False
            writer.add_bullet(line[2:].strip())
        elif line.startswith("|") and line.endswith("|"):
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if all(set(p).issubset({"-", ":", " "}) for p in parts):
                # Ligne séparatrice de tableau
                continue
            if not in_table:
                in_table = True
                table_headers = parts
                col_w = USABLE_WIDTH / max(len(parts), 1)
                writer.add_table_row(parts, [col_w] * len(parts), is_header=True)
            else:
                col_w = USABLE_WIDTH / max(len(parts), 1)
                writer.add_table_row(parts, [col_w] * len(parts), is_header=False)
        else:
            in_table = False
            # Nettoyer markdown inline pour le paragraphe
            clean_text = re.sub(r"\*\*(.*?)\*\*", r"\1", line)
            clean_text = re.sub(r"\*(.*?)\*", r"\1", clean_text)
            clean_text = re.sub(r"`(.*?)`", r"\1", clean_text)
            writer.add_paragraph(clean_text)

    pdf_bytes = writer.compile()
    pdf_path.write_bytes(pdf_bytes)
    print(
        f"[SUCCESS] PDF DAT généré : {pdf_path} ({len(pdf_bytes)} octets, {writer.page_number} pages)"
    )


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    md_file = root / "docs" / "architecture" / "DAT_SECURIGLASS_FACTORY_OS.md"
    pdf_file = root / "docs" / "architecture" / "DAT_SECURIGLASS_FACTORY_OS.pdf"
    convert_dat_markdown_to_pdf(md_file, pdf_file)
