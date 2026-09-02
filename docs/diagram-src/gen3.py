"""Figures 7, 8, 9: risk engine, deployment, trust boundaries.

See gen1.py for the pattern; this file follows the same shape.
"""
from diagrams import *
D={}

def dia(x,y,w,h,t1,t2=None):
    s=(f'<path d="M{x+w/2},{y} L{x+w},{y+h/2} L{x+w/2},{y+h} L{x},{y+h/2} Z" fill="#ffffff" '
       f'stroke="{MUTED}" stroke-width="1"/>')
    if t2:
        s+=lab(x+w/2,y+h/2-2,t1,10.5,INK,SANS,"middle","600")
        s+=lab(x+w/2,y+h/2+11,t2,9,MUTED,MONO,"middle")
    else:
        s+=lab(x+w/2,y+h/2+4,t1,10.5,INK,SANS,"middle","600")
    return s

def pill(x,y,w,t,c):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="26" rx="13" fill="{c[1]}" stroke="{c[0]}" '
            f'stroke-width="1.2"/><text x="{x+w/2}" y="{y+17.5}" font-family="{MONO}" font-size="9.5" '
            f'font-weight="600" fill="{c[0]}" text-anchor="middle" letter-spacing="1">{t}</text>')

CRIT=(ACCENT,"rgba(235,108,54,0.10)"); NORM=(MUTED,"#ffffff")

# ---------- 7. risk engine flowchart ----------
h=470; s=head(h)
s+=lab(0,12,"FIGURE 07",8,SOFT,MONO,ls=1.6)
s+=box(300,30,160,46,"RawFinding",None,accent=True)
s+=arr(380,76,380,96)
s+=box(255,96,250,42,"Look up algorithms.yaml","base_classical, base_quantum")
s+=arr(380,138,380,158)
s+=box(150,158,220,44,"classical axis","+ param_penalty, clamp 0..10")
s+=box(400,158,220,44,"quantum axis","from NIST IR 8547 status")
s+=f'<path d="M380,138 L260,138 L260,156" fill="none" stroke="{MUTED}" stroke-width="1" marker-end="url(#a)"/>'
s+=f'<path d="M380,138 L510,138 L510,156" fill="none" stroke="{MUTED}" stroke-width="1" marker-end="url(#a)"/>'
s+=arr(260,202,260,222); s+=arr(510,202,510,222)
s+=box(150,222,220,42,"x w_context x w_exposure",None)
s+=box(400,222,220,42,"x w_context x w_exposure",None)
s+=f'<path d="M260,264 L260,284 L380,284" fill="none" stroke="{MUTED}" stroke-width="1"/>'
s+=f'<path d="M510,264 L510,284 L380,284" fill="none" stroke="{MUTED}" stroke-width="1"/>'
s+=arr(380,284,380,300,None)
s+=dia(290,300,180,62,"max(classical, quantum)")
s+=arr(380,362,380,382)
s+=f'<rect x="150" y="378" width="470" height="58" rx="4" fill="rgba(235,108,54,0.05)" stroke="{ACCENT}" stroke-width="1.2" stroke-dasharray="4 3"/>'
s+=lab(162,395,"CAP RULES OVERRIDE",8.5,ACCENT,MONO,ls=1.4)
s+=lab(162,412,"broken algorithm / hardcoded key / cert verify disabled   =>   CRITICAL",9,MUTED,MONO)
s+=lab(162,428,"no findings on either axis   =>   capped at LOW",9,MUTED,MONO)
s+=pill(636,30,104,"CRITICAL",CRIT)
s+=pill(636,64,104,">= 9.0",NORM)
s+=lab(688,110,"HIGH  7.0 - 8.9",9,MUTED,MONO,"middle")
s+=lab(688,128,"MEDIUM  4.0 - 6.9",9,MUTED,MONO,"middle")
s+=lab(688,146,"LOW  < 4.0",9,MUTED,MONO,"middle")
s+=lab(30,340,"Never averaged.",10,ACCENT,SANS,"start","600")
s+=lab(30,354,"An average hides",9,SOFT,SANS)
s+=lab(30,367,"RSA-2048, which is",9,SOFT,SANS)
s+=lab(30,380,"the finding that",9,SOFT,SANS)
s+=lab(30,393,"matters most.",9,SOFT,SANS)
D['risk']=s+'</svg>'

# ---------- 8. deployment ----------
h=340; s=head(h)
s+=lab(0,12,"FIGURE 08",8,SOFT,MONO,ls=1.6)
s+=zone(20,28,720,240,"docker compose up   (one command, the slide 4 claim)",ACCENT)
s+=box(50,62,190,84,"dashboard","served by the API",eyebrow="static files")
s+=lab(145,132,"no build step",9,SOFT,MONO,"middle")
s+=box(285,62,190,84,"backend","uvicorn : 8000",eyebrow="container",accent=True)
s+=lab(380,132,"USER ecdat, non root",9,ACCENT,MONO,"middle")
s+=box(520,62,190,84,"weak-tls-nginx","TLS 1.0, weak ciphers",eyebrow="demo target")
s+=lab(615,132,"local, no public host",9,SOFT,MONO,"middle")
s+=box(285,180,190,64,"ecdat-data","SQLite file",eyebrow="volume")
s+=box(50,180,190,64,"knowledge/","YAML, bundled",eyebrow="read only mount")
s+=box(520,180,190,64,"samples/","vulnerable repo, certs",eyebrow="read only mount")
s+=arr(242,104,283,104,"/api",LINK)
s+=arr(380,146,380,178,"persist")
s+=arr(240,212,283,212,"rules")
s+=arr(518,212,477,212,"scan")
s+=arr(478,104,518,104,"authorised probe",ACCENT)
s+=lab(380,300,"No outbound network call except to the scan target itself. Rules and schema are bundled,",9.5,SOFT,SANS,"middle")
s+=lab(380,314,"so the whole stack runs with the cable unplugged. That is the data sovereignty claim, discharged.",9.5,SOFT,SANS,"middle")
D['deploy']=s+'</svg>'

# ---------- 9. trust boundaries ----------
h=400; s=head(h)
s+=lab(0,12,"FIGURE 09",8,SOFT,MONO,ls=1.6)
s+=zone(20,28,350,150,"untrusted zone")
s+=box(45,62,145,50,"Scan targets","attacker influenced")
s+=box(210,62,140,50,"Repo content","data, not authority")
s+=lab(45,140,"Repository files, certificates and TLS",9,SOFT,SANS)
s+=lab(45,153,"banners are inputs. Never instructions.",9,SOFT,SANS)
s+=zone(390,28,350,150,"trusted zone",ACCENT)
s+=box(415,62,145,50,"API + Engine","authenticated")
s+=box(580,62,140,50,"Audit log","append only",accent=True)
s+=lab(415,140,"JWT gated writes. Every scan request",9,SOFT,SANS)
s+=lab(415,153,"recorded before any socket opens.",9,SOFT,SANS)
s+=f'<line x1="380" y1="20" x2="380" y2="196" stroke="{ACCENT}" stroke-width="1.4" stroke-dasharray="6 4"/>'
s+=lab(380,208,"TRUST BOUNDARY",8.5,ACCENT,MONO,"middle",ls=1.6)
s+=arr(352,87,413,87,"validated",ACCENT)
s+=f'<rect x="20" y="232" width="720" height="120" rx="5" fill="{PAPER}" stroke="{RULE}"/>'
s+=lab(36,252,"KEY MATERIAL HANDLING",8.5,ACCENT,MONO,ls=1.6)
cols=[("Detected literal","never persisted"),
      ("Stored instead","path, line, entropy"),
      ("Plus","4 chars + SHA-256 stub"),
      ("Verified by","grep of DB and reports")]
for i,(a,b) in enumerate(cols):
    x=40+i*180
    s+=lab(x,276,a,10,INK,SANS,"start","600")
    s+=lab(x,292,b,8.8,MUTED,MONO)
    if i<3: s+=f'<line x1="{x+165}" y1="266" x2="{x+165}" y2="300" stroke="{RULE}" stroke-width="1"/>'
s+=lab(36,325,"The test asserts zero hits. If a sample secret appears anywhere in the database or in a generated report,",9,SOFT,SANS)
s+=lab(36,339,"the claim on slide 4 is false and the build is broken, not the test.",9,SOFT,SANS)
D['trust']=s+'</svg>'
open('svg3.py','w').write(repr(D))
print("gen3 ok", list(D))
