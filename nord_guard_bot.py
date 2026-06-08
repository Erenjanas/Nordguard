#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NORD Guard - Üst Düzey Telegram Güvenlik & Moderasyon Botu
Render uyumlu | OpenAI GPT-4o-mini ile AI analizi
Author: AI Assistant
Version: 2.0.0
"""

import logging
import re
import asyncio
import json
import os
import time
import random
import string
import traceback
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Optional, Dict, List, Set

from telegram import (
    Update, ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup,
    ChatMemberAdministrator, ChatMemberOwner
)
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters
)
from telegram.constants import ChatType

# ───────────────────────────────
# ENV DESTEĞİ (Render uyumlu)
# ───────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ───────────────────────────────
# KONFİGÜRASYON
# ───────────────────────────────
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
ADMIN_IDS = [int(x.strip()) for x in os.getenv("ADMIN_IDS", "").split(",") if x.strip()] if os.getenv("ADMIN_IDS") else []
LOG_CHANNEL = os.getenv("LOG_CHANNEL", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# AI analiz ayarları
AI_ENABLED = os.getenv("AI_ENABLED", "true").lower() == "true"
AI_RISK_THRESHOLD = int(os.getenv("AI_RISK_THRESHOLD", "60"))  # AI skoru bu üstündeyse müdahale
AI_MAX_MSG_PER_MIN = int(os.getenv("AI_MAX_MSG_PER_MIN", "30"))  # Dakikada max AI analizi (maliyet kontrolü)

# Risk skoru eşikleri
RISK_LOW = 21
RISK_MEDIUM = 41
RISK_HIGH = 61
RISK_CRITICAL = 81

# Ceza süreleri (saniye)
MUTE_10MIN = 600
MUTE_1HOUR = 3600
MUTE_1DAY = 86400

# Flood limitleri
FLOOD_MSG_COUNT = 5
FLOOD_TIME_WINDOW = 10
FLOOD_MUTE_DURATION = 300

# Spam limitleri
MAX_EMOJI_COUNT = 10
MAX_CAPS_RATIO = 0.7
MAX_MSG_LENGTH = 2000

# ───────────────────────────────
# VERİ DEPOLAMA (JSON - Render'da kalıcı disk yok, 
# ama /tmp yazılabilir. Üretimde Redis/DB kullan)
# ───────────────────────────────
DATA_DIR = os.getenv("DATA_DIR", "/tmp/nordguard_data")
os.makedirs(DATA_DIR, exist_ok=True)

def load_json(filename: str) -> dict:
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, Exception):
            return {}
    return {}

def save_json(filename: str, data: dict):
    path = os.path.join(DATA_DIR, filename)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error(f"Save error: {e}")

# ───────────────────────────────
# GLOBAL VERİ YAPILARI
# ───────────────────────────────
user_violations = defaultdict(lambda: defaultdict(int))
user_mute_history = defaultdict(list)
message_history = defaultdict(list)
join_history = defaultdict(list)
new_members = defaultdict(set)
user_captcha = {}
raid_mode = defaultdict(bool)
protection_level = defaultdict(lambda: "normal")
module_status = defaultdict(lambda: defaultdict(bool))
ai_usage_counter = defaultdict(list)  # {chat_id: [timestamp, ...]} - AI rate limit

# ───────────────────────────────
# AI ANALİZ FONKSİYONU (OpenAI)
# ───────────────────────────────

async def ai_analyze_message(text: str, user_id: int, chat_id: int, context: ContextTypes.DEFAULT_TYPE) -> Optional[dict]:
    """OpenAI GPT ile mesajı analiz et."""
    if not AI_ENABLED or not OPENAI_API_KEY:
        return None

    # Rate limit kontrolü
    now = time.time()
    ai_usage_counter[chat_id] = [t for t in ai_usage_counter[chat_id] if now - t < 60]
    if len(ai_usage_counter[chat_id]) >= AI_MAX_MSG_PER_MIN:
        return None  # Limit aşıldı, klasik analiz devam etsin

    ai_usage_counter[chat_id].append(now)

    system_prompt = """Sen NORD Guard adlı Telegram moderasyon botusun. 
Görevin mesajları analiz edip risk skoru ve kategori belirlemek.

Kategoriler: Guvenli, Supheli, Spam, Reklam, Dolandiricilik, Kufur, Taciz, Tehdit, NefretSoylemi, ZararliIcerik

Risk skoru: 0-100 arası tam sayı.

Kurallar:
- Kufur/hakaret: 40-70 puan
- Spam/flood: 20-50 puan  
- Reklam: 30-60 puan
- Dolandiricilik: 70-100 puan
- Tehdit: 80-100 puan
- Nefret soylemi: 70-100 puan
- Normal sohbet: 0-20 puan
- Saka/komik icerik: 0-30 puan (agresif olma)
- Kripto/yatirim vaadi: 60-100 puan
- Davet linki: 30-60 puan

Sadece JSON formatinda yanıt ver. Ornek:
{"risk_score": 45, "category": "Kufur", "reason": "Hafif küfür içeriyor", "action": "warn"}

action değerleri: ignore, warn, delete, mute, ban
"""

    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            payload = {
                "model": OPENAI_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Mesaj: \"{text}\"\nKullanıcı ID: {user_id}\nGrup ID: {chat_id}"}
                ],
                "temperature": 0.1,
                "max_tokens": 150,
                "response_format": {"type": "json_object"}
            }
            headers = {
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            }
            async with session.post(
                "https://api.openai.com/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    content = result["choices"][0]["message"]["content"]
                    analysis = json.loads(content)
                    analysis["ai_processed"] = True
                    return analysis
                else:
                    logging.warning(f"AI API error: {resp.status}")
                    return None
    except Exception as e:
        logging.error(f"AI analysis error: {e}")
        return None

# ───────────────────────────────
# KÜFÜR / HAKARET FİLTRELERİ
# ───────────────────────────────
TURKISH_SWEARS = [
    "amk", "aq", "amq", "amcık", "yarrak", "sik", "siktir", "sikerim", "sikik",
    "siktim", "sikem", "siktiğim", "orospu", "orospunun", "evladı", "pezevenk",
    "kahpe", "dalyarak", "göt", "götveren", "yavşak", "şerefsiz", "piç", "keko",
    "mal", "aptal", "gerizekalı", "salak", "bok", "boktan", "siktirgit", "siktr",
    "s2k", "s2kirim", "skrm", "skik", "amına", "amini", "amkoyim", "amkoyayim",
    "oc", "oç", "o.c", "o.c.", "orsbu", "orsbu çocuğu", "orsbu evladı",
    "gavat", "kezban", "yosma", "fahişe", "fahise", "orosbucoc", "orsbcoc",
    "sulaleni", "sülaleni", "siker", "sikerrim", "sikerr", "sikiyim", "siktimin",
    "siktiğimin", "siktiğim", "siktiğimnin", "siktiğimn",
    "pezevengin", "pezevenk", "pezeven", "pezevengin", "pezevenkler",
    "yarram", "yarragi", "yarrag", "yarrağı", "yarrakçı", "yarrakçılık",
    "götveren", "götverenler", "götü", "götün", "götünü", "götüne",
    "amcık", "amcıklar", "amcığa", "amcığın", "amcıkçı", "amcıkçılık",
    "sikik", "sikikler", "sikmiş", "siktim", "siktimin", "siktiğim",
    "orospu", "orospular", "orospunun", "orospuluk", "orospuçocuğu",
    "piç", "piçler", "piçin", "piçlik", "piç kurusu", "piçin",
    "kahpe", "kahpeler", "kahpenin", "kahpelik",
    "dalyarak", "dalyaraklar", "dalyarağın",
    "yavşak", "yavşaklar", "yavşağın", "yavşaklık",
    "şerefsiz", "şerefsizler", "şerefsizin", "şerefsizlik",
    "gerzek", "gerzekler", "gerzegin", "gerzeklik",
    "ibne", "ibneler", "ibnenin", "ibnelik",
    "keko", "kekolar", "kekoyum", "kekoluk",
    "mal", "mallar", "malın", "mallık",
    "aptal", "aptallar", "aptalın", "aptallık",
    "salak", "salaklar", "salakın", "salaklık",
    "gerizekalı", "gerizekalılar", "gerizekalının", "gerizekalılık",
    "bok", "boklar", "bokun", "boktan", "boklu", "boklarım",
    "siktir", "siktirler", "siktirin", "siktirgit", "siktirolgit",
    "s2k", "s2kirim", "s2ktir", "s2kem", "s2kik", "s2ktiğim",
    "amk", "amkler", "amkın", "amkoyim", "amkoyayim", "amkoyum",
    "aq", "a.q", "a.q.", "amq", "amqın", "amqoyim",
    "oç", "o.c", "o.c.", "oc", "ocuk", "ocların",
    "ananı", "anani", "anan", "ananiaviadini", "anani sikerim",
    "babanı", "babani", "baban", "babani sikerim",
    "sülaleni", "sulaleni", "sülalenin", "sulalenin",
    "sikerim", "siker", "sikiyim", "siktim", "siktiğim",
    "siktiğimin", "siktiğimnin", "siktiğimn", "siktiğim",
    "sikem", "sikemiyim", "sikemem", "sikemez",
    "sikik", "sikikler", "sikiksin", "sikikli",
    "sikmiş", "sikmişim", "sikmişler", "sikmişsin",
    "siktimin", "siktiminin", "siktiminler",
    "siktiğim", "siktiğimin", "siktiğimnin", "siktiğimn",
]

ENGLISH_SWEARS = [
    "fuck", "fucking", "fucked", "fucker", "fuckin", "fck", "fcking", "fcked",
    "shit", "shitting", "shitty", "sh1t", "sh1tty", "sh1tting",
    "bitch", "bitches", "b1tch", "b1tches", "biatch",
    "asshole", "assholes", "a$$hole", "a$$holes", "arsehole",
    "bastard", "bastards", "b4stard", "b4stards",
    "damn", "d4mn", "dammit", "d4mmit",
    "cunt", "cunts", "c0nt", "c0nts",
    "dick", "dicks", "d1ck", "d1cks", "dickhead", "dickheads",
    "pussy", "pussies", "pu$$y", "pu$$ies",
    "whore", "whores", "wh0re", "wh0res",
    "slut", "sluts", "slvt", "slvts",
    "retard", "retards", "ret4rd", "ret4rds", "retarded",
    "idiot", "idiots", "1diot", "1diots",
    "stupid", "stvpid", "stup1d",
    "moron", "morons", "m0ron", "m0rons",
    "dumb", "dvmv", "d1mb",
    "loser", "losers", "l0ser", "l0sers",
    "trash", "tr4sh",
    "garbage", "g4rbage",
    "scum", "scvmbag", "scumbag",
    "prick", "pricks", "pr1ck", "pr1cks",
    "twat", "twats", "tw4t", "tw4ts",
    "bollocks", "b0llocks",
    "wanker", "wankers", "w4nker", "w4nkers",
    "cock", "cocks", "c0ck", "c0cks", "cockhead",
    "motherfucker", "motherfuckers", "mthrfcker", "mthrfckr",
    "nigga", "nigger", "n1gga", "n1gger", "n1gg4",
    "fag", "fags", "f4g", "f4gs", "faggot", "f4ggot",
    "gay", "g4y", "homo", "h0mo", "lesbo", "lesb0",
]

CHAR_MAP = {
    'a': '[a@4âäàáãå]', 'e': '[e3êëèé€]', 'i': '[i1!îïìíı]',
    'o': '[o0ôöòóõ]', 'u': '[uûüùú]', 's': '[s$5ß]', 'g': '[g9ğ]',
    'c': '[cç]', 't': '[t7]', 'l': '[l1£]', 'r': '[r®]',
    'b': '[b8]', 'n': '[nñ]', 'k': '[kκ]', 'm': '[mµ]',
    'h': '[h#]', 'd': '[dð]', 'p': '[p¶]', 'y': '[y¥]',
    'z': '[z2]', 'w': '[wω]', 'v': '[vν]', 'x': '[x×]',
    'f': '[fƒ]', 'j': '[jʝ]', 'q': '[q¶]',
}

def normalize_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r'[^\w\s]', '', text)
    text = re.sub(r'\s+', '', text)
    return text

def contains_swear(text: str) -> tuple[bool, str]:
    normalized = normalize_text(text)
    for swear in TURKISH_SWEARS:
        pattern = swear.replace(' ', '')
        if pattern in normalized:
            return True, swear
    for swear in ENGLISH_SWEARS:
        pattern = swear.replace(' ', '')
        if pattern in normalized:
            return True, swear
    for swear in TURKISH_SWEARS + ENGLISH_SWEARS:
        clean = swear.replace(' ', '')
        regex = ''
        for char in clean:
            if char in CHAR_MAP:
                regex += CHAR_MAP[char]
            else:
                regex += char
        try:
            if re.search(regex, normalized):
                return True, swear
        except re.error:
            continue
    return False, ""

# ───────────────────────────────
# SPAM / FLOOD / REKLAM FİLTRELERİ
# ───────────────────────────────

def is_flood(chat_id: int, user_id: int, text: str) -> bool:
    now = time.time()
    key = chat_id
    message_history[key].append((user_id, text, now))
    cutoff = now - FLOOD_TIME_WINDOW
    message_history[key] = [m for m in message_history[key] if m[2] > cutoff]
    user_msgs = [m for m in message_history[key] if m[0] == user_id]
    if len(user_msgs) >= FLOOD_MSG_COUNT:
        return True
    if len(user_msgs) >= 3:
        last_texts = [m[1] for m in user_msgs[-3:]]
        if len(set(last_texts)) == 1:
            return True
    return False

def is_emoji_spam(text: str) -> bool:
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"
        "\U0001F300-\U0001F5FF"
        "\U0001F680-\U0001F6FF"
        "\U0001F1E0-\U0001F1FF"
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "]+", flags=re.UNICODE
    )
    emojis = emoji_pattern.findall(text)
    total_emojis = sum(len(e) for e in emojis)
    return total_emojis > MAX_EMOJI_COUNT

def is_caps_spam(text: str) -> bool:
    if len(text) < 10:
        return False
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return False
    caps = [c for c in letters if c.isupper()]
    return len(caps) / len(letters) > MAX_CAPS_RATIO

def contains_invite_link(text: str) -> bool:
    patterns = [
        r't\.me\/\+?[a-zA-Z0-9_]+',
        r'telegram\.me\/\+?[a-zA-Z0-9_]+',
        r'telegram\.dog\/\+?[a-zA-Z0-9_]+',
        r't\.me\/joinchat\/[a-zA-Z0-9_-]+',
        r'telegram\.me\/joinchat\/[a-zA-Z0-9_-]+',
    ]
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False

def contains_external_link(text: str) -> bool:
    platforms = [
        r'discord\.(gg|com|invite)',
        r'whatsapp\.com',
        r'wa\.me',
        r'instagram\.com',
        r'facebook\.com',
        r'twitter\.com',
        r'x\.com',
        r'tiktok\.com',
        r'youtube\.com',
        r'youtu\.be',
    ]
    for p in platforms:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False

def is_suspicious_url(text: str) -> bool:
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link']
    for s in shorteners:
        if s in text.lower():
            return True
    phishing_keywords = [
        'free', 'win', 'prize', 'gift', 'claim', 'verify', 'login',
        'password', 'account', 'update', 'urgent', 'click here',
        'limited time', 'congratulations', 'you won', 'winner',
        'ücretsiz', 'hediye', 'kazandın', 'ödül', 'tıkla', 'giriş',
        'şifre', 'hesap', 'doğrula', 'acil', 'sınırlı süre',
    ]
    text_lower = text.lower()
    for kw in phishing_keywords:
        if kw in text_lower:
            return True
    return False

def is_scam(text: str) -> bool:
    scam_patterns = [
        r'\b(kripto|crypto|bitcoin|btc|ethereum|eth)\b.*kazanç|kar|profit|earn',
        r'\b(yatırım|investment)\b.*garanti|guaranteed|kesin',
        r'\b(çekiliş|çekilis|giveaway|draw)\b.*kazanan|winner|katıl|join',
        r'\b(ücretsiz|free)\b.*(bitcoin|btc|kripto|crypto|para|money)',
        r'\b(garanti|guaranteed)\b.*(kazanç|profit|kar|para|money)',
        r'\b(2x|3x|5x|10x)\b.*(garanti|guaranteed|kesin)',
        r'\b(airdrop)\b.*(ücretsiz|free|claim)',
        r'\b(scam|rug|pump|dump)\b.*(join|katıl|grup|group)',
        r'\b(hesap|account)\b.*(çal|hack|steal|hackle)',
        r'\b(phishing|oltalama)\b',
        r'\b(sosyal mühendislik|social engineering)\b',
        r'\b(şifre|password)\b.*(iste|request|ver|give)',
        r'\b(özel mesaj|dm|private)\b.*(detay|detail|bilgi|info)',
        r'\b(admin|yetkili|moderator)\b.*(olduğunu|claim|pretend)',
        r'\b(destek|support)\b.*(hesabın|account)\b.*(askıya|suspend)',
        r'\b(verify|doğrula|onayla)\b.*(account|hesap)',
    ]
    text_lower = text.lower()
    for pattern in scam_patterns:
        if re.search(pattern, text_lower):
            return True
    return False

def is_harassment(text: str) -> tuple[bool, str]:
    harassment_keywords = [
        ("irkçı", ["zenci", "siyahı", "arap", "çingene", "çingen", "yahudi", "ermeni",
                   "kürt", "laz", "çerkez", "ırk", "ırkçı", "ırkçılık", "ırk ayrımı",
                   "nigger", "negro", "black", "white", "asian", "racist", "racism"]),
        ("cinsiyetçi", ["kadın", "erkek", "cinsiyet", "cinsiyetçi", "cinsiyetçilik",
                         "feminist", "feminizm", "erkek adam", "kadın işi", "sexist",
                         "sexism", "gender", "misogyn", "misandry"]),
        ("tehdit", ["öldür", "öldürmek", "keserim", "vururum", "döverim", "kırarım",
                    "yakarım", "patlatırım", "tehdit", "tehdit etmek", "tehdit ederim",
                    "kill", "murder", "attack", "hurt", "destroy", "burn", "threat",
                    "threaten", "i will kill", "i will hurt", "i will destroy"]),
        ("nefret", ["nefret", "nefret ediyorum", "nefret söylemi", "hate", "hate speech",
                    "hateful", "hatred", "i hate", "fuck you all", "die", "kill yourself"]),
    ]
    text_lower = text.lower()
    for category, keywords in harassment_keywords:
        for kw in keywords:
            if kw in text_lower:
                return True, category
    return False, ""

# ───────────────────────────────
# RİSK SKORU HESAPLAMA (Klasik + AI)
# ───────────────────────────────

async def calculate_risk_score(text: str, user_id: int, chat_id: int, context: ContextTypes.DEFAULT_TYPE) -> tuple[int, List[str], str]:
    score = 0
    reasons = []
    category = "Guvenli"
    ai_result = None

    # AI analizi (eşzamansız, beklemeden klasik analiz devam etsin)
    if AI_ENABLED and OPENAI_API_KEY:
        try:
            ai_result = await asyncio.wait_for(
                ai_analyze_message(text, user_id, chat_id, context),
                timeout=3.0
            )
        except asyncio.TimeoutError:
            pass

    # Klasik analiz
    has_swear, swear_word = contains_swear(text)
    if has_swear:
        score += 40
        reasons.append(f"Kufur/hakaret: {swear_word}")
        category = "Kufur"

    if is_emoji_spam(text):
        score += 20
        reasons.append("Emoji spamı")
        if category == "Guvenli":
            category = "Spam"

    if is_caps_spam(text):
        score += 15
        reasons.append("Buyuk harf spamı")
        if category == "Guvenli":
            category = "Spam"

    if contains_invite_link(text):
        score += 30
        reasons.append("Telegram davet linki")
        category = "Reklam"

    if contains_external_link(text):
        score += 20
        reasons.append("Harici platform reklamı")
        if category == "Guvenli":
            category = "Reklam"

    if is_scam(text):
        score += 50
        reasons.append("Dolandiricilik suphesi")
        category = "Dolandiricilik"

    if is_suspicious_url(text):
        score += 25
        reasons.append("Supheli link")
        if category == "Guvenli":
            category = "Supheli"

    is_harass, harass_type = is_harassment(text)
    if is_harass:
        score += 45
        reasons.append(f"Taciz/nefret soylemi: {harass_type}")
        if harass_type == "tehdit":
            category = "Tehdit"
        else:
            category = "NefretSoylemi"

    if is_flood(chat_id, user_id, text):
        score += 20
        reasons.append("Flood")
        if category == "Guvenli":
            category = "Spam"

    if text.count('\n') > 5 or len(text) > MAX_MSG_LENGTH:
        score += 10
        reasons.append("Uzun/zincir mesaj")

    if chat_id in new_members and user_id in new_members[chat_id]:
        if 'http' in text.lower() or 'www' in text.lower() or contains_invite_link(text):
            score += 15
            reasons.append("Yeni uye link paylasimi")

    # AI sonucunu entegre et
    if ai_result and ai_result.get("ai_processed"):
        ai_score = ai_result.get("risk_score", 0)
        ai_category = ai_result.get("category", "Guvenli")
        ai_reason = ai_result.get("reason", "")

        # AI skoru yüksekse onu öncelikli al
        if ai_score >= AI_RISK_THRESHOLD:
            # Ağırlıklı ortalama (AI %60, Klasik %40)
            combined_score = int(ai_score * 0.6 + min(score, 100) * 0.4)
            score = combined_score
            if ai_reason:
                reasons.append(f"AI: {ai_reason}")
            if ai_category != "Guvenli":
                category = ai_category

    return min(score, 100), reasons, category

# ───────────────────────────────
# CEZA SİSTEMİ
# ───────────────────────────────

async def apply_mute(update: Update, context: ContextTypes.DEFAULT_TYPE, 
                     user_id: int, duration: int, reason: str):
    chat_id = update.effective_chat.id
    try:
        until_date = datetime.now() + timedelta(seconds=duration)
        permissions = ChatPermissions(can_send_messages=False)
        await context.bot.restrict_chat_member(
            chat_id=chat_id,
            user_id=user_id,
            permissions=permissions,
            until_date=until_date
        )
        await log_action(context, chat_id, "MUTE", user_id, reason, duration)
    except Exception as e:
        logging.error(f"Mute error: {e}")

async def apply_ban(update: Update, context: ContextTypes.DEFAULT_TYPE,
                    user_id: int, reason: str, permanent: bool = True):
    chat_id = update.effective_chat.id
    try:
        if permanent:
            await context.bot.ban_chat_member(chat_id=chat_id, user_id=user_id)
        else:
            until_date = datetime.now() + timedelta(days=1)
            await context.bot.ban_chat_member(
                chat_id=chat_id, user_id=user_id, until_date=until_date
            )
        await log_action(context, chat_id, "BAN", user_id, reason)
    except Exception as e:
        logging.error(f"Ban error: {e}")

async def apply_warn(update: Update, context: ContextTypes.DEFAULT_TYPE,
                     user_id: int, reason: str):
    chat_id = update.effective_chat.id
    user_violations[chat_id][user_id] += 1
    count = user_violations[chat_id][user_id]

    if count == 1:
        msg = f"⚠️ Uyari {count}/5: {reason}"
    elif count == 2:
        await apply_mute(update, context, user_id, MUTE_10MIN, reason)
        msg = f"🔇 10 dakika susturuldu ({count}/5 ihlal): {reason}"
    elif count == 3:
        await apply_mute(update, context, user_id, MUTE_1HOUR, reason)
        msg = f"🔇 1 saat susturuldu ({count}/5 ihlal): {reason}"
    elif count == 4:
        await apply_mute(update, context, user_id, MUTE_1DAY, reason)
        msg = f"🔇 1 gun susturuldu ({count}/5 ihlal): {reason}"
    else:
        await apply_ban(update, context, user_id, reason)
        msg = f"⛔ Kalici ban ({count} ihlal): {reason}"
        user_violations[chat_id][user_id] = 0

    try:
        await context.bot.send_message(chat_id=chat_id, text=msg)
    except Exception as e:
        logging.error(f"Warn message error: {e}")

    await log_action(context, chat_id, "WARN", user_id, reason, count)

async def log_action(context: ContextTypes.DEFAULT_TYPE, chat_id: int, 
                     action: str, user_id: int, reason: str, extra=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "action": action,
        "chat_id": chat_id,
        "user_id": user_id,
        "reason": reason,
        "extra": extra
    }

    logs = load_json("moderation_logs.json")
    logs.setdefault(str(chat_id), []).append(log_entry)
    save_json("moderation_logs.json", logs)

    if LOG_CHANNEL:
        try:
            extra_str = f" | Ek: {extra}" if extra else ""
            text = (f"🛡️ NORD Guard Log\n"
                    f"Eylem: {action}\n"
                    f"Kullanici: {user_id}\n"
                    f"Grup: {chat_id}\n"
                    f"Sebep: {reason}{extra_str}\n"
                    f"Zaman: {timestamp}")
            await context.bot.send_message(chat_id=LOG_CHANNEL, text=text)
        except Exception as e:
            logging.error(f"Log channel error: {e}")

# ───────────────────────────────
# YETKİLİ KONTROLÜ
# ───────────────────────────────

async def is_admin(chat_id: int, user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
        return isinstance(member, (ChatMemberOwner, ChatMemberAdministrator))
    except Exception:
        return False

async def is_bot_admin(chat_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    try:
        bot_member = await context.bot.get_chat_member(chat_id, context.bot.id)
        return isinstance(bot_member, (ChatMemberOwner, ChatMemberAdministrator))
    except Exception:
        return False

# ───────────────────────────────
# CAPTCHA SİSTEMİ
# ───────────────────────────────

def generate_captcha() -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

async def send_captcha(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int):
    chat_id = update.effective_chat.id
    code = generate_captcha()
    user_captcha[(chat_id, user_id)] = code

    keyboard = [[InlineKeyboardButton(code, callback_data=f"captcha_{user_id}_{code}")]]
    wrong_codes = []
    for _ in range(3):
        wrong = generate_captcha()
        while wrong == code or wrong in wrong_codes:
            wrong = generate_captcha()
        wrong_codes.append(wrong)
        keyboard.append([InlineKeyboardButton(wrong, callback_data=f"captcha_{user_id}_{wrong}")])

    random.shuffle(keyboard)

    await context.bot.send_message(
        chat_id=chat_id,
        text=f"🔐 Hos geldin! Spam korumasi icin dogru kodu sec:\n"
             f"Dogru kodu bul ve grupta konusmaya basla.",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

    try:
        permissions = ChatPermissions(
            can_send_messages=False,
            can_send_media_messages=False,
            can_send_polls=False,
            can_send_other_messages=False,
            can_add_web_page_previews=False,
            can_change_info=False,
            can_invite_users=False,
            can_pin_messages=False
        )
        await context.bot.restrict_chat_member(chat_id, user_id, permissions)
    except Exception as e:
        logging.error(f"Captcha restrict error: {e}")

# ───────────────────────────────
# MESAJ İŞLEYİCİ (ANA MOTOR)
# ───────────────────────────────

async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.effective_chat:
        return

    chat_id = update.effective_chat.id
    user_id = update.message.from_user.id
    text = update.message.text or update.message.caption or ""

    if await is_admin(chat_id, user_id, context):
        return

    if not await is_bot_admin(chat_id, context):
        return

    if not module_status[chat_id].get("guard", True):
        return

    if raid_mode[chat_id]:
        if user_id in new_members.get(chat_id, set()):
            try:
                await update.message.delete()
            except Exception:
                pass
            return

    # Risk analizi (AI + Klasik)
    score, reasons, category = await calculate_risk_score(text, user_id, chat_id, context)

    # Agir ihlaller -> Direkt ban
    if category in ["Dolandiricilik", "Tehdit", "NefretSoylemi", "ZararliIcerik"]:
        if score >= RISK_HIGH:
            try:
                await update.message.delete()
            except Exception:
                pass
            await apply_ban(update, context, user_id, f"{category}: {', '.join(reasons)}")
            return

    # Kritik risk -> Ban
    if score >= RISK_CRITICAL:
        try:
            await update.message.delete()
        except Exception:
            pass
        await apply_ban(update, context, user_id, f"Kritik risk ({score}): {', '.join(reasons)}")
        return

    # Yuksek risk -> Mesaj sil + susturma
    if score >= RISK_HIGH:
        try:
            await update.message.delete()
        except Exception:
            pass
        await apply_mute(update, context, user_id, MUTE_1HOUR, f"Yuksek risk ({score}): {', '.join(reasons)}")
        try:
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"🛡️ Yuksek risk mesaj silindi.\nKullanici: {update.message.from_user.mention_html()}\nSebep: {', '.join(reasons)}"
            )
        except Exception:
            pass
        return

    # Orta risk -> Mesaj sil + uyari
    if score >= RISK_MEDIUM:
        try:
            await update.message.delete()
        except Exception:
            pass
        await apply_warn(update, context, user_id, f"Orta risk ({score}): {', '.join(reasons)}")
        return

    # Dusuk risk -> Uyari
    if score >= RISK_LOW:
        if user_violations[chat_id][user_id] == 0:
            await apply_warn(update, context, user_id, f"Dusuk risk ({score}): {', '.join(reasons)}")
        return

# ───────────────────────────────
# YENİ ÜYE İŞLEYİCİ
# ───────────────────────────────

async def new_member_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.effective_chat:
        return

    chat_id = update.effective_chat.id

    for member in update.message.new_chat_members:
        user_id = member.id

        if user_id == context.bot.id:
            continue

        now = time.time()
        join_history[chat_id].append(now)

        recent_joins = [t for t in join_history[chat_id] if now - t < 60]
        if len(recent_joins) >= 5:
            raid_mode[chat_id] = True
            try:
                await context.bot.set_chat_slow_mode(chat_id, 30)
            except Exception:
                pass
            await context.bot.send_message(
                chat_id=chat_id,
                text="🚨 RAID ALARMI! Cok sayida uye girisi tespit edildi.\n"
                     "Sohbet yavas moda alindi. Yeni uye girisleri sinirlandi."
            )

        new_members[chat_id].add(user_id)
        await send_captcha(update, context, user_id)

# ───────────────────────────────
# CAPTCHA CALLBACK
# ───────────────────────────────

async def captcha_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    data = query.data
    parts = data.split("_")
    if len(parts) != 3 or parts[0] != "captcha":
        return

    target_user_id = int(parts[1])
    code = parts[2]

    chat_id = update.effective_chat.id
    user_id = query.from_user.id

    if user_id != target_user_id:
        await query.edit_message_text("❌ Bu captcha sana ait degil!")
        return

    correct_code = user_captcha.get((chat_id, user_id))

    if code == correct_code:
        try:
            permissions = ChatPermissions(
                can_send_messages=True,
                can_send_media_messages=True,
                can_send_polls=True,
                can_send_other_messages=True,
                can_add_web_page_previews=True,
                can_invite_users=True
            )
            await context.bot.restrict_chat_member(chat_id, user_id, permissions)
            await query.edit_message_text("✅ Dogrulama basarili! Konusmaya baslayabilirsin.")
        except Exception as e:
            logging.error(f"Captcha unrestrict error: {e}")
    else:
        await query.edit_message_text("❌ Yanlis kod! Lutfen tekrar dene.")

# ───────────────────────────────
# ADMIN KOMUTLARI
# ───────────────────────────────

async def cmd_guard_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    module_status[update.effective_chat.id]["guard"] = True
    await update.message.reply_text("✅ NORD Guard aktif!")

async def cmd_guard_off(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    module_status[update.effective_chat.id]["guard"] = False
    await update.message.reply_text("⛔ NORD Guard devre disi.")

async def cmd_antispam_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    module_status[update.effective_chat.id]["antispam"] = True
    await update.message.reply_text("✅ Anti-spam aktif!")

async def cmd_antiflood_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    module_status[update.effective_chat.id]["antiflood"] = True
    await update.message.reply_text("✅ Anti-flood aktif!")

async def cmd_antilink_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    module_status[update.effective_chat.id]["antilink"] = True
    await update.message.reply_text("✅ Anti-link aktif!")

async def cmd_antiraid_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    module_status[update.effective_chat.id]["antiraid"] = True
    await update.message.reply_text("✅ Anti-raid aktif!")

async def cmd_protection_max(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    protection_level[update.effective_chat.id] = "max"
    for key in ["guard", "antispam", "antiflood", "antilink", "antiraid"]:
        module_status[update.effective_chat.id][key] = True
    await update.message.reply_text("🛡️ Maksimum koruma aktif! Tum moduller acik.")

async def cmd_protection_normal(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    protection_level[update.effective_chat.id] = "normal"
    for key in ["guard", "antispam", "antiflood", "antilink"]:
        module_status[update.effective_chat.id][key] = True
    module_status[update.effective_chat.id]["antiraid"] = False
    await update.message.reply_text("🛡️ Normal koruma aktif.")

async def cmd_protection_custom(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    protection_level[update.effective_chat.id] = "custom"
    await update.message.reply_text("⚙️ Ozel koruma modu. Modulleri manuel ac/kapat.")

async def cmd_mute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("Bir mesaja yanit vererek kullan.")
        return
    target = update.message.reply_to_message.from_user.id
    duration = 3600
    if context.args:
        try:
            duration = int(context.args[0]) * 60
        except ValueError:
            pass
    await apply_mute(update, context, target, duration, "Admin mute")
    await update.message.reply_text(f"🔇 Kullanici susturuldu ({duration//60} dk).")

async def cmd_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("Bir mesaja yanit vererek kullan.")
        return
    target = update.message.reply_to_message.from_user.id
    try:
        permissions = ChatPermissions(
            can_send_messages=True,
            can_send_media_messages=True,
            can_send_polls=True,
            can_send_other_messages=True,
            can_add_web_page_previews=True,
            can_invite_users=True
        )
        await context.bot.restrict_chat_member(update.effective_chat.id, target, permissions)
        await update.message.reply_text("🔊 Kullanici susturmasi kaldirildi.")
    except Exception as e:
        await update.message.reply_text(f"Hata: {e}")

async def cmd_ban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("Bir mesaja yanit vererek kullan.")
        return
    target = update.message.reply_to_message.from_user.id
    await apply_ban(update, context, target, "Admin ban")
    await update.message.reply_text("⛔ Kullanici banlandi.")

async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not context.args:
        await update.message.reply_text("Kullanici ID'si gir: /unban 123456789")
        return
    try:
        target = int(context.args[0])
        await context.bot.unban_chat_member(update.effective_chat.id, target)
        await update.message.reply_text("✅ Ban kaldirildi.")
    except Exception as e:
        await update.message.reply_text(f"Hata: {e}")

async def cmd_warn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("Bir mesaja yanit vererek kullan.")
        return
    target = update.message.reply_to_message.from_user.id
    reason = " ".join(context.args) if context.args else "Admin uyarisi"
    await apply_warn(update, context, target, reason)

async def cmd_clearwarns(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("Bir mesaja yanit vererek kullan.")
        return
    target = update.message.reply_to_message.from_user.id
    chat_id = update.effective_chat.id
    user_violations[chat_id][target] = 0
    await update.message.reply_text("🧹 Kullanici uyarilari temizlendi.")

async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    chat_id = update.effective_chat.id
    logs = load_json("moderation_logs.json")
    chat_logs = logs.get(str(chat_id), [])

    actions = Counter([log["action"] for log in chat_logs])
    stats_text = "📊 NORD Guard Istatistikleri\n\n"
    for action, count in actions.most_common():
        stats_text += f"{action}: {count}\n"
    stats_text += f"\nToplam: {len(chat_logs)} islem"

    await update.message.reply_text(stats_text)

async def cmd_security(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    chat_id = update.effective_chat.id
    status = module_status[chat_id]
    level = protection_level[chat_id]
    raid = "🚨 AKTIF" if raid_mode[chat_id] else "✅ Pasif"
    ai_status = "🤖 AKTIF" if (AI_ENABLED and OPENAI_API_KEY) else "❌ Devre disi"

    text = (f"🛡️ NORD Guard Guvenlik Durumu\n\n"
            f"Koruma Seviyesi: {level.upper()}\n"
            f"Raid Modu: {raid}\n"
            f"AI Analiz: {ai_status}\n\n"
            f"Moduller:\n"
            f"  Guard: {'✅' if status.get('guard') else '❌'}\n"
            f"  Anti-Spam: {'✅' if status.get('antispam') else '❌'}\n"
            f"  Anti-Flood: {'✅' if status.get('antiflood') else '❌'}\n"
            f"  Anti-Link: {'✅' if status.get('antilink') else '❌'}\n"
            f"  Anti-Raid: {'✅' if status.get('antiraid') else '❌'}\n")

    await update.message.reply_text(text)

async def cmd_ai_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    chat_id = update.effective_chat.id
    now = time.time()
    ai_usage_counter[chat_id] = [t for t in ai_usage_counter[chat_id] if now - t < 60]
    usage = len(ai_usage_counter[chat_id])

    text = (f"🤖 AI Analiz Durumu\n\n"
            f"Model: {OPENAI_MODEL}\n"
            f"Aktif: {'✅' if AI_ENABLED else '❌'}\n"
            f"Son 1 dk kullanim: {usage}/{AI_MAX_MSG_PER_MIN}\n"
            f"Risk esigi: {AI_RISK_THRESHOLD}\n\n"
            f"AI analizi, klasik filtrelerle birlikte calisir.\n"
            f"Yuksek riskli mesajlar oncelikli AI tarafindan degerlendirilir.")
    await update.message.reply_text(text)

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ NORD Guard\n"
        "Ust duzey Telegram guvenlik ve moderasyon botu.\n\n"
        "Beni gruba admin olarak ekle ve /protection max yaz."
    )

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = """
🛡️ NORD Guard Komutlari

Admin Komutlari:
/guard on/off - Koruma ac/kapat
/antispam on - Spam korumasi
/antiflood on - Flood korumasi
/antilink on - Link korumasi
/antiraid on - Raid korumasi
/protection max - Maksimum koruma
/protection normal - Normal koruma
/protection custom - Ozel koruma

Moderasyon:
/mute [dk] - Sustur (yanitla)
/unmute - Susturma kaldir (yanitla)
/ban - Ban (yanitla)
/unban <id> - Ban kaldir
/warn [sebep] - Uyar (yanitla)
/clearwarns - Uyarilari temizle (yanitla)

Bilgi:
/stats - Istatistikler
/security - Guvenlik durumu
/ai_status - AI analiz durumu

Kurulum:
1. Beni gruba ekle
2. Admin yetkisi ver (mesaj silme, uye banlama, mesaj sabitleme)
3. /protection max yaz
    """
    await update.message.reply_text(help_text)

# ───────────────────────────────
# HATA YAKALAMA
# ───────────────────────────────

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logging.error(f"Update {update} caused error {context.error}")
    logging.error(traceback.format_exc())

# ───────────────────────────────
# RENDER HEALTH CHECK (Web sunucu)
# ───────────────────────────────

async def health_check(request):
    """Render health check endpoint'i."""
    from aiohttp import web
    return web.Response(text="NORD Guard is running! 🛡️")

async def start_web_server():
    """Render için web sunucusu başlat."""
    from aiohttp import web
    app = web.Application()
    app.router.add_get("/", health_check)
    app.router.add_get("/health", health_check)

    port = int(os.getenv("PORT", "8080"))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    logging.info(f"Web server started on port {port}")
    return runner

# ───────────────────────────────
# ANA FONKSİYON
# ───────────────────────────────

def main():
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO
    )

    if not BOT_TOKEN:
        logging.error("BOT_TOKEN bulunamadi! Environment variable ayarla.")
        return

    application = Application.builder().token(BOT_TOKEN).build()

    # Komutlar
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("help", cmd_help))
    application.add_handler(CommandHandler("guard", cmd_guard_on, filters=filters.Regex("on")))
    application.add_handler(CommandHandler("guard", cmd_guard_off, filters=filters.Regex("off")))
    application.add_handler(CommandHandler("antispam", cmd_antispam_on))
    application.add_handler(CommandHandler("antiflood", cmd_antiflood_on))
    application.add_handler(CommandHandler("antilink", cmd_antilink_on))
    application.add_handler(CommandHandler("antiraid", cmd_antiraid_on))
    application.add_handler(CommandHandler("protection", cmd_protection_max, filters=filters.Regex("max")))
    application.add_handler(CommandHandler("protection", cmd_protection_normal, filters=filters.Regex("normal")))
    application.add_handler(CommandHandler("protection", cmd_protection_custom, filters=filters.Regex("custom")))
    application.add_handler(CommandHandler("mute", cmd_mute))
    application.add_handler(CommandHandler("unmute", cmd_unmute))
    application.add_handler(CommandHandler("ban", cmd_ban))
    application.add_handler(CommandHandler("unban", cmd_unban))
    application.add_handler(CommandHandler("warn", cmd_warn))
    application.add_handler(CommandHandler("clearwarns", cmd_clearwarns))
    application.add_handler(CommandHandler("stats", cmd_stats))
    application.add_handler(CommandHandler("security", cmd_security))
    application.add_handler(CommandHandler("ai_status", cmd_ai_status))

    # Callback
    application.add_handler(CallbackQueryHandler(captcha_callback, pattern="^captcha_"))

    # Mesajlar
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
    application.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, new_member_handler))

    # Hata
    application.add_error_handler(error_handler)

    print("🛡️ NORD Guard baslatiliyor...")

    # Render'da web sunucusu + polling birlikte çalışsın
    if os.getenv("RENDER"):
        loop = asyncio.get_event_loop()
        web_runner = loop.run_until_complete(start_web_server())
        try:
            application.run_polling(allowed_updates=Update.ALL_TYPES)
        finally:
            loop.run_until_complete(web_runner.cleanup())
    else:
        application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
