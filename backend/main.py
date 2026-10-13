import asyncio
import csv
import io
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).resolve().parent.parent


def load_env() -> None:
    """อ่าน configs/.env (ไม่ต้องพึ่ง python-dotenv); ค่าใน environment จริงมีสิทธิ์เหนือไฟล์"""
    path = ROOT / "configs" / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


load_env()

import db  # noqa: E402
import line_notifier  # noqa: E402
import mock_generator  # noqa: E402
import sniffer  # noqa: E402
from detectors import KINDS, Event  # noqa: E402
from engine import Engine  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from schemas import AttackType, Incident, Severity  # noqa: E402


class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()

    async def broadcast(self, msg: dict) -> None:
        dead = []
        for ws in self.clients:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)


hub = Hub()


async def publish(inc: Incident) -> None:
    inc = db.insert_incident(inc)
    await hub.broadcast({"type": "incident", "data": inc.model_dump(mode="json")})
    asyncio.create_task(line_notifier.notify(inc))


async def mock_loop() -> None:
    import random
    interval = float(os.getenv("MOCK_INTERVAL_SEC", "6"))
    tick = 0
    while True:
        await asyncio.sleep(1)
        tick += 1
        await hub.broadcast({"type": "frames", "data": mock_generator.make_frame_counts()})
        if tick % max(1, int(interval)) == 0 and random.random() < 0.8:
            await publish(mock_generator.make_incident())


def load_config() -> dict:
    path = ROOT / "configs" / "config.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


engine: Optional[Engine] = None
active_sensors: dict[str, dict] = {}


def record_sensor(name: str, accepted: int, online: Optional[bool] = None, port: Optional[str] = None) -> None:
    now = time.time()
    # ใช้ port เป็น key หลัก เพื่อให้ 1 พอร์ตจริง มีรายการบน Dashboard เพียง 1 ตัวเสมอ
    key = port if port else name
    cur = active_sensors.get(key, {"events_total": 0})
    is_online = online if online is not None else True
    active_sensors[key] = {
        "name": name,
        "port": port,
        "last_seen": now,
        "events_total": cur.get("events_total", 0) + accepted,
        "last_count": accepted,
        "online": is_online,
    }
    if accepted > 0:
        print(f"📡 [SENSOR] จาก {name}: รับ {accepted} events (รวมสะสม: {active_sensors[key]['events_total']})")


def get_online_sensors(now: float) -> list[dict]:
    """คืนเฉพาะเซนเซอร์ที่กำลังเชื่อมต่อและออนไลน์อยู่จริง กำจัดเซนเซอร์ผีทิ้ง"""
    dead_keys = [
        k for k, v in list(active_sensors.items())
        if not v.get("online", False) or (now - v.get("last_seen", 0) > 15)
    ]
    for k in dead_keys:
        active_sensors.pop(k, None)

    return [
        {
            "name": v["name"],
            "port": v.get("port") or "",
            "online": True,
            "total": v.get("events_total", 0),
            "last_seen_sec": int(now - v["last_seen"]),
        }
        for k, v in active_sensors.items()
    ]


async def live_loop() -> None:
    """ส่งสถิติเฟรมต่อวินาทีให้กราฟ และสถานะ sensor ภายนอก"""
    cfg = load_config()
    has_laptop = bool(cfg.get("interface") and os.name != "nt")
    while True:
        await asyncio.sleep(1)
        now = time.time()
        s_list = get_online_sensors(now)
        warmup = engine.grace_remaining() if engine else 0
        await hub.broadcast({
            "type": "frames",
            "data": engine.pop_frame_counts(),
            "sensors": s_list,
            "laptop_sniffer": has_laptop,
            "warmup_sec": warmup,
        })


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine
    db.init_db()
    loop = asyncio.get_running_loop()
    cfg = load_config()
    # engine ถูกเรียกจาก thread ของ sniffer จึงต้องส่งเข้า event loop อย่างปลอดภัย
    engine = Engine(cfg, lambda inc: asyncio.run_coroutine_threadsafe(publish(inc), loop))
    task, threads = None, []
    if os.getenv("MODE", "mock") == "mock":
        task = asyncio.create_task(mock_loop())
    else:
        task = asyncio.create_task(live_loop())
        threads = sniffer.start_all(engine, cfg, on_sensor=record_sensor)
    yield
    if task:
        task.cancel()
    for t in threads:
        t.stop()


app = FastAPI(title="Wi-Fi Micro-WIDS", lifespan=lifespan)
static_dir = ROOT / "frontend" / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


def check_token(token: Optional[str]) -> None:
    required = os.getenv("DASHBOARD_TOKEN")
    if required and token != required:
        raise HTTPException(status_code=401, detail="invalid token")


@app.get("/")
def index():
    return FileResponse(ROOT / "frontend" / "index.html")


@app.get("/api/status")
def status():
    c = db.counts_by_severity()
    now = time.time()
    cfg = load_config()
    has_laptop = bool(cfg.get("interface") and os.name != "nt")
    sensors_info = get_online_sensors(now)
    warmup = engine.grace_remaining() if engine else 0
    return {"mode": os.getenv("MODE", "mock"), "counts": c, "total": sum(c.values()),
            "line_configured": bool(os.getenv("LINE_CHANNEL_ACCESS_TOKEN")),
            "laptop_sniffer": has_laptop,
            "sensors": sensors_info,
            "warmup_sec": warmup}


@app.post("/api/clear")
def clear_history(x_token: Optional[str] = Header(None)):
    """ล้างประวัติเหตุการณ์ทั้งหมด (สำหรับเริ่มต้นการทดสอบใหม่)"""
    check_token(x_token)
    db.clear_all()
    return {"status": "ok"}


@app.get("/api/incidents")
def incidents(limit: int = 200, q: Optional[str] = None):
    return db.list_incidents(min(limit, 1000), q)


@app.get("/api/export.csv")
def export_csv(q: Optional[str] = None):
    rows = db.list_incidents(100000, q)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["id"] + db.COLUMNS)
    w.writeheader()
    w.writerows(rows)
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=incidents.csv"},
    )


@app.post("/api/simulate")
async def simulate(attack: Optional[AttackType] = None, x_token: Optional[str] = Header(None)):
    """สร้างเหตุการณ์จำลองตามต้องการ (ใช้ทดสอบ UI / LINE)"""
    check_token(x_token)
    inc = mock_generator.make_incident(attack)
    await publish(inc)
    return inc


class IngestEvent(BaseModel):
    kind: str
    ts: Optional[float] = None
    src: str = ""
    dst: str = ""
    bssid: str = ""
    ssid: str = ""
    channel: int = 0
    rssi: int = 0
    extra: dict = {}


class IngestBody(BaseModel):
    sensor: str = "remote"
    events: list[IngestEvent]


@app.post("/api/ingest")
def ingest(body: IngestBody, x_token: Optional[str] = Header(None)):
    """รับ event จาก sensor ภายนอก (ESP32 / เครื่องที่ 2) — ดู docs/SENSOR_PROTOCOL.md"""
    check_token(x_token)
    if len(body.events) > 500:
        raise HTTPException(status_code=413, detail="max 500 events per request")
    accepted = 0
    now = time.time()
    for e in body.events:
        if e.kind not in KINDS:
            continue
        engine.feed(Event(e.kind, e.ts or now, e.src, e.dst, e.bssid, e.ssid,
                          e.channel, e.rssi, e.extra), source=f"sensor:{body.sensor}")
        accepted += 1

    cur = active_sensors.get(body.sensor, {"events_total": 0})
    active_sensors[body.sensor] = {
        "name": body.sensor,
        "port": None,
        "last_seen": now,
        "events_total": cur.get("events_total", 0) + accepted,
        "last_count": accepted,
        "online": True,
    }
    print(f"📡 [INGEST] จาก {body.sensor}: รับ {accepted} events (รวมสะสม: {active_sensors[body.sensor]['events_total']})")
    return {"accepted": accepted, "rejected": len(body.events) - accepted}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    hub.clients.add(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive
    except WebSocketDisconnect:
        pass
    finally:
        hub.clients.discard(ws)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))
