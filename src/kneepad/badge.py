"""Static 'protected by kneepad' SVG badge, generated locally with no network access."""

from __future__ import annotations

from xml.sax.saxutils import escape


def _text_width(s: str) -> int:
    # Verdana 11px is about 6.6px per character on average; add padding.
    return int(len(s) * 6.6) + 12


def make_badge(label: str = "protected by", message: str = "kneepad", color: str = "#2da44e") -> str:
    lw, rw = _text_width(label), _text_width(message)
    w = lw + rw
    lx, rx = lw / 2, lw + rw / 2
    lab, msg = escape(label), escape(message)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{lab}: {msg}">'
        f"<title>{lab}: {msg}</title>"
        '<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        '<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{w}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{rw}" height="20" fill="{color}"/><rect width="{w}" height="20" fill="url(#s)"/></g>'
        '<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lx}" y="15" fill="#010101" fill-opacity=".3">{lab}</text><text x="{lx}" y="14">{lab}</text>'
        f'<text x="{rx}" y="15" fill="#010101" fill-opacity=".3">{msg}</text><text x="{rx}" y="14">{msg}</text>'
        "</g></svg>\n"
    )
