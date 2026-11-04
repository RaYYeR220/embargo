import os,sys,json
sys.path.insert(0,'.')
from desk.config import DeskConfig
from desk.agents.intake import IntakeAgent
from desk.guard_client import GuardClient
rooms=json.load(open('work/desk-rooms.json')); os.environ['INTAKE_ROOM_ID']=rooms['INTAKE_ROOM_ID']
cfg=DeskConfig.from_env()
ia=IntakeAgent(cfg); ia.connect()
# a couple of reports to populate the feed + leave one case open
ia.handle_report("snap-slop","Buffer overflow in libcurl %s leading to RCE"%ia.index.latest,"mallory")
out=ia.handle_report("snap-real","Use-after-free in libcurl 8.11.0 cookie jar parsing on duplicate Set-Cookie","alice")
# a benign allowed message inside the case room, and a blocked leak in intake
import httpx
case=out.get("room_id")
try: ia.agent.post(case,"status: setting up the reproduction environment")
except Exception: pass
try: ia.agent.post(cfg.intake_room_id,"the bug is: Use-after-free in libcurl 8.11.0 cookie jar parsing on duplicate Set-Cookie")
except httpx.HTTPStatusError: pass
ia.agent.stop()
g=GuardClient(cfg.guard_url,cfg.guard_key)
snap={"cases":g.cases()["cases"],"audit":g.audit(40)["decisions"]}
json.dump(snap,open("web/snapshot.json","w"),indent=1)
print("cases:",len(snap["cases"]),"audit:",len(snap["audit"]))
