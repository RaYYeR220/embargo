import os,sys,json
sys.path.insert(0,'.')
from desk.config import DeskConfig
from desk.agents.intake import IntakeAgent
rooms=json.load(open('work/desk-rooms.json'))
os.environ['INTAKE_ROOM_ID']=rooms['INTAKE_ROOM_ID']
cfg=DeskConfig.from_env()
ia=IntakeAgent(cfg)
ia.connect()
print("latest curl:", ia.index.latest)
# (a) slop: latest version, scary memory claim with no grounding
slop = "Critical Buffer Overflow in libcurl %s leading to RCE via crafted response" % ia.index.latest
r1 = ia.handle_report("rpt-slop-1", slop, "mallory")
print("SLOP ->", r1.get("verdict"), "|", r1.get("reason","")[:80])
# (b) plausible: a real-ish claim against an older version + specific area
plausible = "Use-after-free in libcurl 8.11.0 websocket frame handling when server closes mid-read"
r2 = ia.handle_report("rpt-real-1", plausible, "alice")
print("PLAUSIBLE ->", r2.get("verdict"), "| case:", r2.get("case_id"), "room:", r2.get("room_id","")[:8])
ia.agent.stop()
print("GUARD CASES:", json.dumps(ia.guard.cases(), indent=1)[:400])
