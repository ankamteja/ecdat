"""Figures 10, 11: scoring provenance and the NIST migration timeline.

See gen1.py for the pattern; this file follows the same shape.
"""
from diagrams import *
D={}

# ---------- 10. scoring provenance ----------
h=380; s=head(h)
s+=lab(0,12,"FIGURE 10",8,SOFT,MONO,ls=1.6)
srcs=[(20,"MITRE CWSS","metric group structure","Structure"),
      (205,"SSL Labs guide","weights, bands, caps","Mechanics"),
      (390,"NIST IR 8547","2030 / 2035 dates","Timeline"),
      (575,"CWE 310/326/327","finding taxonomy","Taxonomy")]
for x,n,sb,ey in srcs:
    s+=box(x,34,165,66,n,sb,eyebrow=ey)
s+=f'<path d="M102,100 L102,128 L380,128 L380,166" fill="none" stroke="{MUTED}" stroke-width="1"/>'
s+=f'<path d="M287,100 L287,128 L380,128" fill="none" stroke="{MUTED}" stroke-width="1"/>'
s+=f'<path d="M472,100 L472,128 L380,128" fill="none" stroke="{MUTED}" stroke-width="1"/>'
s+=f'<path d="M657,100 L657,128 L380,128" fill="none" stroke="{MUTED}" stroke-width="1"/>'
s+=f'<line x1="380" y1="128" x2="380" y2="164" stroke="{ACCENT}" stroke-width="1.2" marker-end="url(#aa)"/>'
s+=box(230,166,300,66,"ECDAT dual axis model","classical + quantum, never averaged",accent=True)
s+=arr(380,232,380,258,None,ACCENT)
outs=[(90,"Severity band","CRITICAL to LOW"),(290,"PQC readiness","percentage + migration"),(490,"Years remaining","to NIST disallowment")]
for x,n,sb in outs:
    s+=box(x,258,180,58,n,sb)
s+=f'<path d="M380,246 L180,246 L180,256" fill="none" stroke="{ACCENT}" stroke-width="1" marker-end="url(#aa)"/>'
s+=f'<path d="M380,246 L580,246 L580,256" fill="none" stroke="{ACCENT}" stroke-width="1" marker-end="url(#aa)"/>'
s+=lab(380,348,"No published CVSS equivalent exists for cryptographic weakness. So the model is assembled from",9.5,SOFT,SANS,"middle")
s+=lab(380,362,"four published sources rather than invented, which is what makes a score defensible under questioning.",9.5,SOFT,SANS,"middle")
D['prov']=s+'</svg>'

# ---------- 11. IR 8547 timeline ----------
h=330; s=head(h)
s+=lab(0,12,"FIGURE 11",8,SOFT,MONO,ls=1.6)
Y=150
s+=f'<line x1="40" y1="{Y}" x2="720" y2="{Y}" stroke="{RULE}" stroke-width="2"/>'
marks=[(70,"2024","FIPS 203/204/205\nfinalised",False),
       (240,"2026","today\nECDAT ships",True),
       (450,"2030","112 bit RSA, ECDSA,\nECDH deprecated",False),
       (690,"2035","disallowed\nNSM-10 target",True)]
for x,yr,t,acc in marks:
    c=ACCENT if acc else MUTED
    s+=f'<circle cx="{x}" cy="{Y}" r="{6 if acc else 4.5}" fill="{"#ffffff"}" stroke="{c}" stroke-width="{1.8 if acc else 1.2}"/>'
    s+=lab(x,Y-26,yr,17,c,SANS,"middle","600")
    for i,ln in enumerate(t.split("\n")):
        s+=lab(x,Y+26+i*13,ln,9,SOFT,MONO,"middle")
s+=f'<rect x="240" y="{Y+58}" width="450" height="20" rx="10" fill="rgba(235,108,54,0.10)"/>'
s+=f'<line x1="240" y1="{Y+68}" x2="248" y2="{Y+68}" stroke="{ACCENT}" stroke-width="1"/>'
s+=f'<line x1="682" y1="{Y+68}" x2="690" y2="{Y+68}" stroke="{ACCENT}" stroke-width="1"/>'
s+=lab(465,Y+72,"9 YEAR MIGRATION WINDOW",9,ACCENT,MONO,"middle","600",ls=1.6)
s+=f'<rect x="40" y="232" width="700" height="70" rx="5" fill="{PAPER}" stroke="{RULE}"/>'
s+=lab(56,254,"WHAT ECDAT PUTS ON THE DASHBOARD",8.5,ACCENT,MONO,ls=1.6)
s+=lab(56,278,"RSA-2048 found in 3 assets.  Deprecated by NIST after 2030, disallowed after 2035.  9 years remaining.",11,INK,MONO)
s+=lab(56,294,"Every element of that sentence is sourced. No tool in the slide 5 comparison matrix produces it.",9,SOFT,SANS)
D['time']=s+'</svg>'
open('svg4.py','w').write(repr(D))
print("gen4 ok", list(D))
