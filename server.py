from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import sqlite3
import secrets
import hashlib
import hmac
import json
from urllib.parse import parse_qsl
from datetime import datetime, timedelta
import uvicorn

BOT_TOKEN = "9107647672:AAGHzFV9t5cRFdFxi__pMW9Sdk7zG8nit04"
ADMIN_IDS = [6618318489, 5802008874]

app = FastAPI()

def init_db():
    conn = sqlite3.connect('app.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            telegram_id TEXT PRIMARY KEY,
            username TEXT,
            hwid TEXT,
            license_key TEXT,
            expires_at TEXT,
            resolution TEXT DEFAULT '1920x1080'
        )
    ''')
    conn.commit()
    conn.close()

init_db()

class AuthRequest(BaseModel):
    initData: str
class HwidRequest(BaseModel):
    initData: str
    hwid: str
class ResolutionRequest(BaseModel):
    initData: str
    resolution: str
class GenKeyRequest(BaseModel):
    initData: str
    target_hwid: str
    days: int
class CheckRequest(BaseModel):
    hwid: str
    key: str

def get_user_from_init(init_data: str):
    try:
        parsed_data = dict(parse_qsl(init_data))
        if 'hash' not in parsed_data: return None
        received_hash = parsed_data.pop('hash')
        data_check_string = '\n'.join(f'{k}={v}' for k, v in sorted(parsed_data.items()))
        secret_key = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
        if calculated_hash != received_hash: return None
        return json.loads(parsed_data.get('user', '{}'))
    except:
        return None

@app.post("/api/auth")
def auth(req: AuthRequest):
    user = get_user_from_init(req.initData)
    if not user: raise HTTPException(status_code=401)
    tg_id = str(user.get('id'))
    username = user.get('username', 'NoName')
    is_admin = tg_id in [str(aid) for aid in ADMIN_IDS]
    conn = sqlite3.connect('app.db')
    res = conn.execute("SELECT hwid, license_key, expires_at, resolution FROM users WHERE telegram_id = ?", (tg_id,)).fetchone()
    if not res:
        conn.execute("INSERT INTO users (telegram_id, username) VALUES (?, ?)", (tg_id, username))
        conn.commit()
        hwid, key, exp, res_val = None, None, None, '1920x1080'
    else:
        hwid, key, exp, res_val = res
    conn.close()
    return {"tg_id": tg_id, "username": username, "hwid": hwid, "key": key, "expires": exp, "resolution": res_val, "is_admin": is_admin}

@app.post("/api/set_hwid")
def set_hwid(req: HwidRequest):
    user = get_user_from_init(req.initData)
    if not user: raise HTTPException(status_code=401)
    conn = sqlite3.connect('app.db')
    conn.execute("UPDATE users SET hwid = ? WHERE telegram_id = ?", (req.hwid, str(user.get('id'))))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.post("/api/set_resolution")
def set_resolution(req: ResolutionRequest):
    user = get_user_from_init(req.initData)
    if not user: raise HTTPException(status_code=401)
    conn = sqlite3.connect('app.db')
    conn.execute("UPDATE users SET resolution = ? WHERE telegram_id = ?", (req.resolution, str(user.get('id'))))
    conn.commit()
    conn.close()
    return {"status": "ok"}

@app.post("/api/genkey")
def genkey(req: GenKeyRequest):
    user = get_user_from_init(req.initData)
    if not user or str(user.get('id')) not in [str(aid) for aid in ADMIN_IDS]: raise HTTPException(status_code=403)
    if req.days > 7: raise HTTPException(status_code=400)
    new_key = secrets.token_hex(6).upper()
    exp = (datetime.now() + timedelta(days=req.days)).isoformat()
    conn = sqlite3.connect('app.db')
    conn.execute("UPDATE users SET license_key = ?, expires_at = ? WHERE hwid = ?", (new_key, exp, req.target_hwid))
    conn.commit()
    conn.close()
    return {"key": new_key, "expires": exp}

@app.post("/api/check")
def check(req: CheckRequest):
    conn = sqlite3.connect('app.db')
    res = conn.execute("SELECT license_key, expires_at, resolution FROM users WHERE hwid = ?", (req.hwid,)).fetchone()
    conn.close()
    if not res or res[0] != req.key: raise HTTPException(status_code=401)
    if datetime.now() > datetime.fromisoformat(res[1]): raise HTTPException(status_code=403)
    return {"status": "ok", "resolution": res[2]}

@app.get("/", response_class=HTMLResponse)
def index():
    return """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <script src="https://telegram.org/js/telegram-web-app.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: sans-serif; }
        body { background-color: #1a1a1f; color: #fff; display: flex; flex-direction: column; padding: 20px 20px 80px 20px; min-height: 100vh; }
        .header { width: 100%; display: flex; justify-content: space-between; margin-bottom: 20px; font-weight: bold; font-size: 18px; }
        .tab-content { display: none; flex-direction: column; align-items: center; width: 100%; }
        .tab-content.active { display: flex; animation: fadeIn 0.3s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
        .card { background: #2a2a30; width: 100%; border-radius: 12px; padding: 15px; margin-bottom: 15px; }
        .label { font-size: 12px; color: #888; margin-bottom: 5px; }
        .value { font-size: 18px; font-weight: bold; word-break: break-all; }
        .timer-container { width: 180px; height: 180px; border-radius: 50%; border: 4px solid #333; display: flex; flex-direction: column; align-items: center; justify-content: center; margin: 20px auto 30px auto; }
        .timer-text { font-size: 30px; font-weight: bold; }
        .input-group { display: flex; gap: 10px; margin-top: 10px; }
        input, select { flex: 1; padding: 12px; background: #1a1a1f; border: 1px solid #444; border-radius: 8px; color: white; font-size: 16px; outline: none; text-align: center; -webkit-appearance: none; }
        button { padding: 12px; border: none; border-radius: 8px; font-size: 14px; font-weight: bold; cursor: pointer; background-color: #ffd700; color: #000; }
        button:active { opacity: 0.8; }
        .status-text { font-size: 20px; font-weight: bold; text-align: center; color: #ffd700; margin-bottom: 10px; }
        .bottom-nav { position: fixed; bottom: 0; left: 0; right: 0; height: 60px; background: #2a2a30; display: flex; justify-content: space-around; align-items: center; border-top: 1px solid #444; z-index: 100; }
        .nav-item { color: #888; font-size: 12px; font-weight: bold; cursor: pointer; display: flex; flex-direction: column; align-items: center; gap: 4px; transition: 0.2s; }
        .nav-item.active { color: #ffd700; }
        .nav-icon { font-size: 20px; }
        .fab { position: fixed; bottom: 80px; right: 20px; background-color: #2ecc71; color: #fff; padding: 12px 20px; border-radius: 30px; font-weight: bold; font-size: 16px; box-shadow: 0 4px 15px rgba(46, 204, 113, 0.4); display: none; align-items: center; gap: 8px; z-index: 1000; border: none; cursor: pointer; transition: transform 0.2s; }
        .fab:active { transform: scale(0.95); }
        .credits { text-align: center; margin-top: 10px; padding: 15px; background: #212126; border-radius: 12px; border: 1px dashed #444; }
        .credit-link { color: #2ecc71; font-weight: bold; cursor: pointer; margin-bottom: 5px; display: block; }
        .credit-link.admin { color: #ffd700; }
    </style>
</head>
<body>
    <div class="header"><div>TokenFarm</div><div id="uname"></div></div>
    <div id="tab-home" class="tab-content active">
        <div class="timer-container"><div class="timer-text" id="timer">--:--:--</div></div>
        <div class="status-text" id="status">Загрузка...</div>
    </div>
    <div id="tab-profile" class="tab-content">
        <div class="card">
            <div class="label">Ваш HWID (Код устройства):</div>
            <div class="value" id="hwid-text">Не привязан</div>
            <div class="input-group" id="hwid-input-group">
                <input type="text" id="hwid-input" placeholder="Введите код">
                <button onclick="saveHwid()">Сохранить</button>
            </div>
        </div>
        <div class="card">
            <div class="label">Разрешение экрана:</div>
            <select id="resolution-select" onchange="saveResolution()">
                <option value="1920x1080">1920 × 1080 (Full HD)</option>
                <option value="2560x1440">2560 × 1440 (2K / QHD)</option>
                <option value="1600x900">1600 × 900 (HD+)</option>
                <option value="1280x720">1280 × 720 (HD)</option>
            </select>
        </div>
        <div class="card" id="key-card" style="display:none;">
            <div class="label">Ваш ключ активации:</div>
            <div class="value" id="key-text" style="color:#ffd700;"></div>
        </div>
        <div class="credits">
            <span class="credit-link" onclick="openTg('ukral_bobs')">Создатель: @ukral_bobs</span>
            <span class="credit-link admin" onclick="openTg('krytoi991')">Админ: @krytoi991</span>
        </div>
    </div>
    <div id="tab-admin" class="tab-content">
        <div class="card">
            <div class="label">Панель администратора</div>
            <div class="input-group"><input type="text" id="admin-hwid" placeholder="HWID пользователя"></div>
            <div class="input-group">
                <select id="admin-days">
                    <option value="1">1 день</option>
                    <option value="2">2 дня</option>
                    <option value="3">3 дня</option>
                    <option value="5">5 дней</option>
                    <option value="7">7 дней</option>
                </select>
                <button onclick="generateKey()">Выдать ключ</button>
            </div>
            <div id="admin-result" style="margin-top:15px; font-weight:bold; color:#00ff00; text-align:center; font-size: 18px;"></div>
        </div>
    </div>
    <button class="fab" id="buy-btn" onclick="buyKey()"><span>🛒</span> Купить ключ</button>
    <div class="bottom-nav">
        <div class="nav-item active" id="nav-home" onclick="switchTab('home')"><span class="nav-icon">⏱</span>Главная</div>
        <div class="nav-item" id="nav-profile" onclick="switchTab('profile')"><span class="nav-icon">👤</span>Профиль</div>
        <div class="nav-item" id="nav-admin" style="display:none;" onclick="switchTab('admin')"><span class="nav-icon">⚙️</span>Админ</div>
    </div>
    <script>
        const tg = window.Telegram.WebApp;
        tg.ready();
        tg.expand();
        const ADMIN_USERNAME = "krytoi991";
        let timerInterval;
        
        function openTg(username) {
            tg.openTelegramLink(`https://t.me/${username}`);
            tg.HapticFeedback.selectionChanged();
        }

        function switchTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            document.getElementById(`tab-${tabName}`).classList.add('active');
            document.getElementById(`nav-${tabName}`).classList.add('active');
            tg.HapticFeedback.selectionChanged();
        }
        function buyKey() {
            tg.HapticFeedback.impactOccurred('light');
            tg.openTelegramLink(`https://t.me/${ADMIN_USERNAME}`);
        }
        function formatTime(ms) {
            if (ms <= 0) return "00:00:00";
            const s = Math.floor(ms / 1000);
            return `${Math.floor(s / 3600).toString().padStart(2, '0')}:${Math.floor((s % 3600) / 60).toString().padStart(2, '0')}:${(s % 60).toString().padStart(2, '0')}`;
        }
        async function initApp() {
            const res = await fetch('/api/auth', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({initData: tg.initData})
            });
            if (!res.ok) { document.getElementById('status').innerText = 'Ошибка'; return; }
            const userData = await res.json();
            document.getElementById('uname').innerText = '@' + userData.username;
            document.getElementById('resolution-select').value = userData.resolution;
            if (userData.is_admin) document.getElementById('nav-admin').style.display = 'flex';
            else document.getElementById('buy-btn').style.display = 'flex';
            if (userData.hwid) {
                document.getElementById('hwid-text').innerText = userData.hwid;
                document.getElementById('hwid-input-group').style.display = 'none';
            } else document.getElementById('hwid-text').innerText = 'Требуется привязка';
            if (userData.key && userData.expires) {
                document.getElementById('key-card').style.display = 'block';
                document.getElementById('key-text').innerText = userData.key;
                startTimer(new Date(userData.expires).getTime());
            } else document.getElementById('status').innerText = 'Нет ключа';
        }
        async function saveHwid() {
            const hwid = document.getElementById('hwid-input').value.trim();
            if (hwid.length < 4) return;
            await fetch('/api/set_hwid', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({initData: tg.initData, hwid: hwid}) });
            document.getElementById('hwid-text').innerText = hwid;
            document.getElementById('hwid-input-group').style.display = 'none';
            tg.HapticFeedback.notificationOccurred('success');
        }
        async function saveResolution() {
            const res = document.getElementById('resolution-select').value;
            await fetch('/api/set_resolution', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({initData: tg.initData, resolution: res}) });
            tg.HapticFeedback.notificationOccurred('success');
        }
        async function generateKey() {
            const hwid = document.getElementById('admin-hwid').value.trim();
            const days = parseInt(document.getElementById('admin-days').value);
            if (hwid.length < 4) return;
            const res = await fetch('/api/genkey', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({initData: tg.initData, target_hwid: hwid, days: days}) });
            if (res.ok) {
                const data = await res.json();
                document.getElementById('admin-result').innerText = `Ключ на ${days} дн.: ${data.key}`;
                tg.HapticFeedback.notificationOccurred('success');
            }
        }
        function startTimer(expiryTime) {
            clearInterval(timerInterval);
            document.getElementById('status').innerText = 'Ключ активен';
            timerInterval = setInterval(() => {
                const diff = expiryTime - new Date().getTime();
                document.getElementById('timer').innerText = formatTime(diff);
                if (diff <= 0) {
                    clearInterval(timerInterval);
                    document.getElementById('status').innerText = 'Ключ истёк';
                }
            }, 1000);
        }
        initApp();
    </script>
</body>
</html>
    """

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000) 
