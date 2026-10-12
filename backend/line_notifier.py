import logging
import os
import time
from datetime import datetime

import httpx

from schemas import Incident, Severity

log = logging.getLogger("line")
PUSH_URL = "https://api.line.me/v2/bot/message/push"
_last_sent: dict[tuple, float] = {}


def _enabled() -> bool:
    return (
        os.getenv("LINE_ALERT_ENABLED", "true").lower() == "true"
        and bool(os.getenv("LINE_CHANNEL_ACCESS_TOKEN"))
        and bool(os.getenv("LINE_USER_ID"))
    )


def should_send(inc: Incident) -> bool:
    """เฉพาะ Critical และไม่ซ้ำ (ประเภท+MAC) ภายในช่วง throttle"""
    if inc.severity is not Severity.CRITICAL:
        return False
    window = float(os.getenv("LINE_THROTTLE_SEC", "60"))
    key = (inc.attack_type, inc.src_mac)
    now = time.time()
    if now - _last_sent.get(key, 0) < window:
        return False
    _last_sent[key] = now
    return True


def format_message(inc: Incident) -> str:
    t = datetime.fromtimestamp(inc.timestamp).strftime("%H:%M:%S")
    return (
        f"🚨 [{inc.severity.value}] {inc.attack_type.value}\n"
        f"เวลา: {t}\nSSID: {inc.ssid} (CH {inc.channel})\n"
        f"Source MAC: {inc.src_mac}\nVictims: {inc.victim_count} | "
        f"Rate: {inc.frame_rate}/s | RSSI: {inc.rssi} dBm\n"
        f"ผลกระทบ: {inc.impact}\nแนะนำ: {inc.action}"
    )


async def notify(inc: Incident) -> None:
    if not _enabled():
        return  # ยังไม่ได้ใส่ Token -> ข้ามเงียบ ๆ
    if not should_send(inc):
        return
    headers = {"Authorization": f"Bearer {os.getenv('LINE_CHANNEL_ACCESS_TOKEN')}"}
    body = {"to": os.getenv("LINE_USER_ID"),
            "messages": [{"type": "text", "text": format_message(inc)}]}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(PUSH_URL, headers=headers, json=body)
            if r.status_code != 200:
                log.warning("LINE push failed: %s %s", r.status_code, r.text)
    except httpx.HTTPError as e:
        log.warning("LINE push error: %s", e)
