"""PDF report rendering.

Jinja2 into HTML, then WeasyPrint into PDF. WeasyPrint needs pango and cairo,
which is why :func:`render` degrades to writing the HTML rather than raising:
a report a reviewer can open in a browser is better than a stack trace.
"""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
)


def render_html(report: dict) -> str:
    """Render the report template to an HTML string."""
    template = _env.get_template("report.html")
    return template.render(
        scan=report["scan"],
        summary=report["summary"],
        pqc=report["pqc_readiness"],
        findings=report["findings"],
        correlations=report["correlations"],
        generated_at=report["generated_at"],
        tool=report["tool"],
    )


def render(report: dict, path: Path) -> tuple[Path, str]:
    """Write a PDF, or fall back to HTML if WeasyPrint is unavailable.

    Returns the path written and the media type, so the caller can serve
    whichever was produced.
    """
    html = render_html(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        from weasyprint import HTML

        HTML(string=html, base_url=str(TEMPLATE_DIR)).write_pdf(str(path))
        return path, "application/pdf"
    except Exception as exc:  # noqa: BLE001 - missing system libraries are expected
        logger.warning("PDF rendering unavailable (%s), writing HTML instead", exc)
        fallback = path.with_suffix(".html")
        fallback.write_text(html, encoding="utf-8")
        return fallback, "text/html"
