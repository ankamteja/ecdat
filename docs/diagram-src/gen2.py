"""Figures 5, 6: data model and scan lifecycle.

See gen1.py for the pattern; this file follows the same shape.
"""
from diagrams import *
D={}

def table(x,y,w,title,fields,accent=False):
    rh=17; h=24+len(fields)*rh
    st=ACCENT if accent else RULE
    s=(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="4" fill="#ffffff" stroke="{st}" '
       f'stroke-width="{1.2 if accent else 1}"/>'
       f'<rect x="{x}" y="{y}" width="{w}" height="24" rx="4" fill="{"rgba(235,108,54,0.10)" if accent else PAPER2}"/>'
       f'<rect x="{x}" y="{y+18}" width="{w}" height="6" fill="{"rgba(235,108,54,0.10)" if accent else PAPER2}"/>'
       f'<text x="{x+8}" y="{y+16}" font-family="{MONO}" font-size="10" font-weight="600" '
       f'fill="{ACCENT if accent else INK}" letter-spacing="0.6">{title}</text>')
    for i,f in enumerate(fields):
        yy=y+24+i*rh
        s+=(f'<line x1="{x}" y1="{yy}" x2="{x+w}" y2="{yy}" stroke="{RULE}" stroke-width="0.5" opacity="0.6"/>'
            f'<text x="{x+8}" y="{yy+12}" font-family="{MONO}" font-size="8.8" fill="{MUTED}">{f}</text>')
    return s,h

# ---------- 5. ER ----------
h=515; s=head(h)
s+=lab(0,12,"FIGURE 05",8,SOFT,MONO,ls=1.6)
t,_=table(20,30,175,"users",["id  PK","username  UNIQUE","password_hash","role"]); s+=t
t,_=table(20,150,175,"audit_log",["id  PK","ts","actor","action","target","detail"]); s+=t
t,_=table(255,30,250,"scans",["id  PK","kind  code|tls|certificate","target","status","authorized_by","started_at / finished_at","error, options_json"],accent=True); s+=t
t,_=table(255,200,250,"assets",["id  PK","scan_id  FK","kind","locator","metadata_json"]); s+=t
t,_=table(255,330,250,"findings",["id  PK","scan_id / asset_id  FK","algorithm, key_size, mode","classical_score, quantum_score","severity, confidence","pqc_vulnerable, standard_refs","dedupe_key  UNIQUE"]); s+=t
t,_=table(565,200,175,"correlations",["id  PK","scan_id  FK","asset_a / asset_b","relation"]); s+=t
t,_=table(565,330,175,"reports",["id  PK","scan_id  FK","format","path, sha256"]); s+=t
s+=arr(197,60,253,60,"1..n")
s+=arr(197,200,253,150,"writes")
s+=arr(380,175,380,198,"1..n",ACCENT)
s+=arr(380,290,380,328,"1..n",ACCENT)
s+=arr(507,240,563,240,"1..n")
s+=arr(507,370,563,370,"1..n")
s+=lab(20,500,"dedupe_key = sha256(kind | locator | algorithm | line_or_port).  audit_log has no UPDATE or DELETE path anywhere in the API.",9,SOFT,MONO)
D['er']=s+'</svg>'

# ---------- 6. sequence ----------
h=420; s=head(h)
s+=lab(0,12,"FIGURE 06",8,SOFT,MONO,ls=1.6)
lanes=[("Analyst",70),("API",210),("Audit",330),("Runner",450),("Scanner",580),("Engine",700)]
for n,x in lanes:
    s+=(f'<rect x="{x-58}" y="30" width="116" height="28" rx="4" fill="#ffffff" stroke="{RULE}"/>'
        f'<text x="{x}" y="49" font-size="11.5" font-weight="600" fill="{INK}" text-anchor="middle">{n}</text>'
        f'<line x1="{x}" y1="58" x2="{x}" y2="378" stroke="{RULE}" stroke-width="1" stroke-dasharray="3 4"/>')
steps=[(70,210,88,"POST /scans {authorized}",ACCENT),
       (210,330,116,"write actor + target",ACCENT),
       (210,70,144,"403 if not authorized",ACCENT),
       (210,450,172,"202 accepted, enqueue",MUTED),
       (450,580,200,"run(job)",MUTED),
       (580,580,228,"stream RawFinding",MUTED),
       (580,700,256,"score each finding",MUTED),
       (700,700,284,"correlate + dedupe",MUTED),
       (700,210,312,"inventory + PQC",MUTED),
       (210,70,340,"GET findings, report.pdf",LINK)]
for x1,x2,y,t,c in steps:
    if x1==x2:
        d = -1 if x1 > 520 else 1
        s+=(f'<path d="M{x1},{y} L{x1+46*d},{y} L{x1+46*d},{y+13} L{x1+4*d},{y+13}" fill="none" '
            f'stroke="{c}" stroke-width="1" marker-end="url(#{"aa" if c==ACCENT else "a"})"/>')
        s+=lab(x1+52*d, y+6, t, 8.5, c, MONO, "start" if d>0 else "end")
    else:
        s+=arr(x1+(4 if x2>x1 else -4),y,x2+(-4 if x2>x1 else 4),y,None,c)
        s+=lab((x1+x2)/2,y-6,t,8.5,c,MONO,"middle")
s+=lab(70,398,"The audit write happens before the socket opens, not after. That ordering is the control.",9,SOFT,SANS)
D['seq']=s+'</svg>'
open('svg2.py','w').write(repr(D))
print("gen2 ok", list(D))
