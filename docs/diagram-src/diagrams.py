"""Shared SVG primitives for the diagram generators.

Small drawing helpers (box, arrow, elbow, label, zone) built on the diagram-
design token system: paper, ink, muted, accent. Not a general purpose
library, just enough to keep gen1-gen4 from repeating raw SVG strings.
Run via build.py, not imported anywhere else in the repository.
"""

# -*- coding: utf-8 -*-
"""ECDAT architecture diagrams, authored on the diagram-design token system."""

INK="#2d3142"; MUTED="#4f5d75"; SOFT="#7a8399"; RULE="#bfc0c0"
ACCENT="#eb6c36"; TINT="rgba(235,108,54,0.08)"; LINK="#2e5aa8"
PAPER="#f5f5f5"; PAPER2="#ececec"; W=760
SANS="'Geist','Noto Sans',Arial,sans-serif"
MONO="'Geist Mono','Noto Sans Mono',monospace"

def head(h, extra=""):
    return (f'<svg viewBox="0 0 {W} {h}" xmlns="http://www.w3.org/2000/svg" '
            f'font-family="{SANS}">'
            '<defs>'
            f'<marker id="a" markerWidth="7" markerHeight="7" refX="6.2" refY="3" orient="auto">'
            f'<path d="M0,0.6 L6,3 L0,5.4 Z" fill="{MUTED}"/></marker>'
            f'<marker id="aa" markerWidth="7" markerHeight="7" refX="6.2" refY="3" orient="auto">'
            f'<path d="M0,0.6 L6,3 L0,5.4 Z" fill="{ACCENT}"/></marker>'
            f'<marker id="al" markerWidth="7" markerHeight="7" refX="6.2" refY="3" orient="auto">'
            f'<path d="M0,0.6 L6,3 L0,5.4 Z" fill="{LINK}"/></marker>'
            f'{extra}</defs>')

def box(x,y,w,h,name,sub=None,eyebrow=None,accent=False,fill=None,dash=False,r=4):
    st=ACCENT if accent else RULE
    fl=fill if fill else ("rgba(235,108,54,0.07)" if accent else "#ffffff")
    d=' stroke-dasharray="3 3"' if dash else ''
    s=(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fl}" '
       f'stroke="{st}" stroke-width="{1.2 if accent else 1}"{d}/>')
    cx=x+w/2; cy=y+h/2
    if eyebrow:
        s+=(f'<text x="{cx}" y="{y+15}" font-family="{MONO}" font-size="8.5" '
            f'letter-spacing="1.5" fill="{ACCENT if accent else SOFT}" text-anchor="middle">'
            f'{eyebrow.upper()}</text>')
        cy = y+h/2+6
    if sub:
        s+=(f'<text x="{cx}" y="{cy-2}" font-size="13" font-weight="600" fill="{INK}" '
            f'text-anchor="middle">{name}</text>')
        s+=(f'<text x="{cx}" y="{cy+12}" font-family="{MONO}" font-size="9.5" fill="{MUTED}" '
            f'text-anchor="middle">{sub}</text>')
    else:
        s+=(f'<text x="{cx}" y="{cy+4.5}" font-size="13" font-weight="600" fill="{INK}" '
            f'text-anchor="middle">{name}</text>')
    return s

def zone(x,y,w,h,label,color=None):
    c=color or SOFT
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="none" '
            f'stroke="{c}" stroke-width="1" stroke-dasharray="4 4" opacity="0.75"/>'
            f'<text x="{x+9}" y="{y+14}" font-family="{MONO}" font-size="8" letter-spacing="1.4" '
            f'fill="{c}">{label.upper()}</text>')

def arr(x1,y1,x2,y2,label=None,color=None,dash=False,mid=None):
    c=color or MUTED
    m="aa" if c==ACCENT else ("al" if c==LINK else "a")
    d=' stroke-dasharray="3.5 3"' if dash else ''
    s=(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{c}" stroke-width="1" '
       f'marker-end="url(#{m})"{d}/>')
    if label:
        lx=(x1+x2)/2 if mid is None else mid[0]
        ly=(y1+y2)/2 if mid is None else mid[1]
        s+=(f'<rect x="{lx-len(label)*2.7-3}" y="{ly-13}" width="{len(label)*5.4+6}" height="12" '
            f'fill="#ffffff" opacity="0.95"/>')
        s+=(f'<text x="{lx}" y="{ly-4}" font-family="{MONO}" font-size="8.5" fill="{c}" '
            f'letter-spacing="0.4" text-anchor="middle">{label}</text>')
    return s

def elbow(x1,y1,x2,y2,label=None,color=None,vfirst=False):
    c=color or MUTED
    m="aa" if c==ACCENT else ("al" if c==LINK else "a")
    p=(f'M{x1},{y1} L{x1},{y2} L{x2},{y2}' if vfirst else f'M{x1},{y1} L{x2},{y1} L{x2},{y2}')
    s=(f'<path d="{p}" fill="none" stroke="{c}" stroke-width="1" marker-end="url(#{m})"/>')
    if label:
        lx,ly=((x1+x2)/2, y2-6) if not vfirst else (x1+6, (y1+y2)/2)
        s+=(f'<text x="{lx}" y="{ly}" font-family="{MONO}" font-size="8.5" fill="{c}" '
            f'text-anchor="middle">{label}</text>')
    return s

def lab(x,y,t,size=9,color=None,fam=None,anchor="start",weight="400",ls=0):
    return (f'<text x="{x}" y="{y}" font-family="{fam or MONO}" font-size="{size}" '
            f'fill="{color or MUTED}" text-anchor="{anchor}" font-weight="{weight}" '
            f'letter-spacing="{ls}">{t}</text>')
