import os,sys,json,httpx
API=os.environ["SWITCH_API"]; GW=API+"/gateway"
c=httpx.Client(timeout=15)
c.post(GW+"/auth/login",json={"email":"admin@switch.local","password":os.environ["ADMIN_PW"]}).raise_for_status()
for name in ["embargo-intake","embargo-disclosure","embargo-reproducer","embargo-fixer"]:
    aid=json.load(open(f"work/{name}.json"))["agent_id"]
    r=c.put(f"{GW}/agents/{aid}/addressing-policy",json={"policy":None})
    print(name, r.status_code)
