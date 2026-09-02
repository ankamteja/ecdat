"""Figures 1, 2, 3, 4: system context, containers, scanner interface, data flow.

Each function builds one SVG string and stores it in the D dict, which
build.py collects. Run standalone only for local iteration; the real entry
point is build.py.
"""
from diagrams import *
D={}

# ---------- 1. C4 L1 system context ----------
h=320; s=head(h)
s+=lab(0,12,"FIGURE 01",8,SOFT,MONO,ls=1.6)
s+=box(300,120,160,80,"ECDAT","single scan platform",accent=True)
s+=box(30,40,150,54,"Security Analyst","authenticates, authorises")
s+=box(30,150,150,54,"Compliance Officer","consumes inventory")
s+=box(30,260,150,54,"CI Pipeline","roadmap, returns 501",dash=True)
s+=box(580,30,150,54,"Source Repositories","git, zip, local dirs")
s+=box(580,105,150,54,"TLS Endpoints","hosts and ports")
s+=box(580,180,150,54,"Certificate Stores","PEM, DER, X.509")
s+=box(580,255,150,54,"CBOM Consumers","CycloneDX 1.6 pipelines")
s+=arr(180,67,298,150,"scan request",ACCENT)
s+=arr(180,177,298,168,"reads findings")
s+=arr(180,287,298,192,None,SOFT,dash=True)
s+=arr(460,150,578,60,"read only")
s+=arr(460,158,578,132,"authorised probe",ACCENT)
s+=arr(460,168,578,207,"parse")
s+=arr(460,182,578,282,"export",LINK)
s+=zone(560,14,190,310,"external to ecdat")
D['ctx']=s+'</svg>'

# ---------- 2. C4 L2 containers ----------
h=400; s=head(h)
s+=lab(0,12,"FIGURE 02",8,SOFT,MONO,ls=1.6)
s+=zone(20,26,720,300,"docker compose network")
s+=box(45,55,150,62,"Dashboard","static, no build step")
s+=box(245,55,180,62,"API","FastAPI + uvicorn",accent=True)
s+=box(475,55,150,62,"Auth","JWT + bcrypt")
s+=box(245,150,180,62,"Scan Runner","ThreadPoolExecutor(4)")
s+=box(45,150,150,62,"Knowledge Base","YAML rules, no code")
s+=box(475,150,150,62,"Risk Engine","dual axis scoring")
s+=box(245,245,180,62,"SQLite","via SQLAlchemy")
s+=box(475,245,150,62,"Reporters","JSON, CBOM, PDF")
s+=box(45,245,150,62,"Audit Log","append only")
s+=arr(197,86,243,86,"/api",LINK)
s+=arr(427,86,473,86)
s+=arr(335,119,335,148,"dispatch",ACCENT)
s+=arr(197,181,243,181,"rules")
s+=arr(427,181,473,181,"findings")
s+=arr(335,214,335,243,"persist")
s+=arr(427,276,473,276,"render")
s+=arr(243,276,197,276,"writes")
s+=lab(380,352,"One application container plus a demo target. SQLite and an in-process runner sit behind interfaces,",9,SOFT,SANS,"middle")
s+=lab(380,366,"so PostgreSQL and a distributed queue remain a configuration change rather than a rewrite.",9,SOFT,SANS,"middle")
D['cont']=s+'</svg>'

# ---------- 3. scanner plugin interface ----------
h=350; s=head(h)
s+=lab(0,12,"FIGURE 03",8,SOFT,MONO,ls=1.6)
s+=box(250,34,260,72,"Scanner","abstract base class",eyebrow="interface",accent=True)
s+=lab(380,96,"validate(target) -> run(job)",9,MUTED,MONO,"middle")
s+=box(30,165,200,74,"CodeScanner","AST, rules, entropy",eyebrow="kind = code")
s+=box(280,165,200,74,"TlsScanner","handshake + cipher probe",eyebrow="kind = tls")
s+=box(530,165,200,74,"CertScanner","PyCA x509",eyebrow="kind = certificate")
for x in (130,380,630):
    s+=f'<path d="M380,106 L380,140 L{x},140 L{x},163" fill="none" stroke="{MUTED}" stroke-width="1" marker-end="url(#a)"/>'
s+=lab(380,133,"implemented by",8.5,SOFT,MONO,"middle")
s+=box(250,272,260,58,"RawFinding","source agnostic record",accent=True)
for x in (130,380,630):
    s+=f'<path d="M{x},239 L{x},258 L380,258 L380,270" fill="none" stroke="{ACCENT}" stroke-width="1" marker-end="url(#aa)"/>'
s+=lab(35,292,"The risk engine and the",9,SOFT,SANS)
s+=lab(35,305,"correlation engine only ever",9,SOFT,SANS)
s+=lab(35,318,"see RawFinding, never a",9,SOFT,SANS)
s+=lab(35,331,"scanner internal.",9,SOFT,SANS)
D['iface']=s+'</svg>'

# ---------- 4. four phase data flow ----------
h=330; s=head(h)
s+=lab(0,12,"FIGURE 04",8,SOFT,MONO,ls=1.6)
xs=[20,205,390,575]; names=["Discovery","Analysis","Risk","Correlate"]
subs=["enumerate assets","identify crypto","score findings","unify and report"]
for i,(x,n,sb) in enumerate(zip(xs,names,subs)):
    s+=box(x,34,165,62,n,sb,eyebrow=f"phase {i+1}",accent=(i==3))
    if i<3: s+=arr(x+165,65,x+203,65)
items={0:["Git repo, ZIP, dir","Host and port","PEM, DER bundle"],
       1:["Python AST walk","Pattern rules","Shannon entropy","TLS + X.509 parse"],
       2:["Classical axis","Quantum axis","Context weighting","Cap rules"],
       3:["Deduplicate","Asset x algorithm","PQC readiness","JSON, CBOM, PDF"]}
for i,x in enumerate(xs):
    for j,t in enumerate(items[i]):
        y=125+j*30
        s+=box(x,y,165,24,"",None,r=3,fill="#ffffff")
        s+=lab(x+10,y+16,t,9.5,MUTED,MONO)
s+=zone(14,110,742,145,"pipeline stages")
s+=lab(380,290,"Each phase reads only the previous phase's output. No stage reaches backwards,",9.5,SOFT,SANS,"middle")
s+=lab(380,304,"which is what allows a fourth scanner to be added without touching the risk engine.",9.5,SOFT,SANS,"middle")
D['flow']=s+'</svg>'
open('svg1.py','w').write(repr(D))
print("gen1 ok", list(D))
