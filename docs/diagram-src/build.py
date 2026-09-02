"""Regenerate the architecture diagrams in docs/images.

    python3 docs/diagram-src/build.py

Diagrams are authored as code rather than drawn, so they can be diffed,
reviewed, and corrected when the implementation changes. Every claim a diagram
makes is meant to be true of the code in the same commit.

Writes both SVG (for the repository and the web) and PNG at 192 dpi (for
slides and documents).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "images"

#: Diagram key to output filename. Order matches the figure numbering.
NAMES: dict[str, str] = {
    "ctx": "01-system-context",
    "cont": "02-containers",
    "iface": "03-scanner-interface",
    "flow": "04-data-flow",
    "er": "05-data-model",
    "seq": "06-scan-lifecycle",
    "risk": "07-risk-engine",
    "deploy": "08-deployment",
    "trust": "09-trust-boundaries",
    "prov": "10-scoring-provenance",
    "time": "11-migration-timeline",
}


def collect() -> dict[str, str]:
    """Run each generator module and merge the diagrams they produce."""
    sys.path.insert(0, str(HERE))
    diagrams: dict[str, str] = {}
    for module in ("gen1", "gen2", "gen3", "gen4"):
        subprocess.run([sys.executable, str(HERE / f"{module}.py")], check=True, cwd=HERE)
        produced = eval((HERE / f"svg{module[-1]}.py").read_text())
        for key, svg in produced.items():
            # Marker ids are global in an HTML document, so namespace them per
            # diagram or arrowheads from one figure leak into another.
            for marker in ("a", "aa", "al"):
                svg = svg.replace(f'id="{marker}"', f'id="{key}_{marker}"')
                svg = svg.replace(f"url(#{marker})", f"url(#{key}_{marker})")
            diagrams[key] = svg
    return diagrams


def write_svg(key: str, svg: str) -> Path:
    # Standalone files need an explicit background; viewers that composite onto
    # a dark surface would otherwise render dark text on dark.
    svg = svg.replace("<defs>", '<rect width="100%" height="100%" fill="#ffffff"/><defs>', 1)
    path = OUT / f"{NAMES[key]}.svg"
    path.write_text(svg)
    return path


def write_png(svg_path: Path) -> Path:
    """Rasterise via a single page PDF.

    WeasyPrint removed write_png in v53, and it is already a project dependency
    for the PDF report, so this avoids adding a rasteriser to the toolchain.
    """
    from weasyprint import HTML

    svg = svg_path.read_text()
    match = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    width, height = (float(match.group(1)), float(match.group(2))) if match else (760.0, 400.0)
    html = (
        f"<style>@page{{size:{width / 96:.4f}in {height / 96:.4f}in;margin:0}}"
        f"body{{margin:0}}svg{{width:{width}px;height:{height}px;display:block}}</style>" + svg
    )
    with tempfile.NamedTemporaryFile(suffix=".pdf") as tmp:
        HTML(string=html).write_pdf(tmp.name)
        subprocess.run(
            ["pdftoppm", "-png", "-r", "192", "-singlefile", tmp.name, str(svg_path.with_suffix(""))],
            check=True,
            capture_output=True,
        )
    return svg_path.with_suffix(".png")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    diagrams = collect()
    missing = set(NAMES) - set(diagrams)
    if missing:
        raise SystemExit(f"generators did not produce: {sorted(missing)}")

    for key in NAMES:
        svg_path = write_svg(key, diagrams[key])
        png_path = write_png(svg_path)
        print(f"{svg_path.name}  {png_path.name}")

    # Intermediate files the generators drop next to themselves.
    for scratch in HERE.glob("svg?.py"):
        scratch.unlink()


if __name__ == "__main__":
    main()
