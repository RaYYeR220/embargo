import os,sys,json,httpx
sys.path.insert(0,'.')
from desk.config import DeskConfig
from desk.switch_client import SwitchAgent
rooms=json.load(open('work/desk-rooms.json')); os.environ['INTAKE_ROOM_ID']=rooms['INTAKE_ROOM_ID']
cfg=DeskConfig.from_env()
a=SwitchAgent(base_url=cfg.api,name=cfg.intake_name,description="x",state_path=cfg.state_dir/f"{cfg.intake_name}.json")
a.register(cfg.reg_token); a.start()
secret="Use-after-free in libcurl 8.11.0 websocket frame handling when server closes mid-read"
# try to leak the case material into the PUBLIC intake room
blocked=False
try:
    a.post(cfg.intake_room_id, "FYI team, the bug is: "+secret)
    print("LEAK NOT BLOCKED (bad)")
except httpx.HTTPStatusError as e:
    blocked=(e.response.status_code==422); print("intake leak blocked:", blocked, "HTTP", e.response.status_code)
a.stop()
