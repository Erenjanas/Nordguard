#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NORD Guard - Üst Düzey Telegram Güvenlik & Moderasyon Botu
Author: AI Assistant
Version: 1.0.0
"""

import logging
import re
import asyncio
import json
import os
import time
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Optional, Dict, List, Set

from telegram import (
    Update, ChatPermissions, InlineKeyboardButton, InlineKeyboardMarkup,
    ChatMemberAdministrator, ChatMemberOwner
)
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters, ConversationHandler
)
from telegram.constants import ChatType

# ───────────────────────────────
# KONFİGÜRASYON
# ───────────────────────────────
BOT_TOKEN = os.getenv("BOT_TOKEN", "SENIN_BOT_TOKENIN")
ADMIN_IDS = list(map(int, os.getenv("ADMIN_IDS", "").split(","))) if os.getenv("ADMIN_IDS") else []
LOG_CHANNEL = os.getenv("LOG_CHANNEL", "")  # Log kanalı ID veya @username

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
FLOOD_TIME_WINDOW = 10  # saniye
FLOOD_MUTE_DURATION = 300  # 5 dakika

# Spam limitleri
MAX_EMOJI_COUNT = 10
MAX_CAPS_RATIO = 0.7
MAX_MSG_LENGTH = 2000

# Yeni üye kısıtlamaları
NEW_MEMBER_RESTRICT_HOURS = 24
NEW_MEMBER_LINK_BAN = True

# ───────────────────────────────
# VERİ DEPOLAMA (Basit JSON)
# ───────────────────────────────
DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

def load_json(filename: str) -> dict:
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_json(filename: str, data: dict):
    path = os.path.join(DATA_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# ───────────────────────────────
# GLOBAL VERİ YAPILARI
# ───────────────────────────────
user_violations = defaultdict(lambda: defaultdict(int))  # {chat_id: {user_id: count}}
user_mute_history = defaultdict(list)  # {user_id: [timestamp, ...]}
message_history = defaultdict(list)  # {chat_id: [(user_id, msg_text, time), ...]}
join_history = defaultdict(list)  # {chat_id: [timestamp, ...]}
new_members = defaultdict(set)  # {chat_id: {user_id, ...}}
user_captcha = {}  # {(chat_id, user_id): captcha_code}
raid_mode = defaultdict(bool)  # {chat_id: True/False}
protection_level = defaultdict(lambda: "normal")  # {chat_id: "max"/"normal"/"custom"}
module_status = defaultdict(lambda: defaultdict(bool))  # {chat_id: {module: True/False}}

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
    "siktimin", "sikemiyim", "siktiğimin", "siktiğim", "siktiğimnin", "siktiğimn",
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
    "siktiğim", "siktiğimin", "siktiğimnin", "siktiğimn",
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

# Normalizasyon haritası (harf değiştirme)
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
    """Küfür tespiti için metni normalize et."""
    text = text.lower()
    # Emoji ve sembolleri kaldır
    text = re.sub(r'[^\w\s]', '', text)
    # Boşlukları temizle
    text = re.sub(r'\s+', '', text)
    return text

def contains_swear(text: str) -> tuple[bool, str]:
    """Metinde küfür/hakaret var mı kontrol et."""
    normalized = normalize_text(text)

    # Türkçe küfürler
    for swear in TURKISH_SWEARS:
        # Tam kelime eşleşmesi veya içerme
        pattern = swear.replace(' ', '')
        if pattern in normalized:
            return True, swear

    # İngilizce küfürler
    for swear in ENGLISH_SWEARS:
        pattern = swear.replace(' ', '')
        if pattern in normalized:
            return True, swear

    # Harf değiştirme ile yazılmışları tespit et (basit versiyon)
    # Örnek: "s1kt1r" -> "sikti"r
    for swear in TURKISH_SWEARS + ENGLISH_SWEARS:
        clean = swear.replace(' ', '')
        # Her karakteri esnek hale getir
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
    """Kullanıcı flood yapıyor mu?"""
    now = time.time()
    key = chat_id

    # Mesaj geçmişini güncelle
    message_history[key].append((user_id, text, now))

    # Eski mesajları temizle
    cutoff = now - FLOOD_TIME_WINDOW
    message_history[key] = [m for m in message_history[key] if m[2] > cutoff]

    # Son X mesajı kontrol et
    user_msgs = [m for m in message_history[key] if m[0] == user_id]
    if len(user_msgs) >= FLOOD_MSG_COUNT:
        return True

    # Aynı mesaj tekrarı
    if len(user_msgs) >= 3:
        last_texts = [m[1] for m in user_msgs[-3:]]
        if len(set(last_texts)) == 1:
            return True

    return False

def is_emoji_spam(text: str) -> bool:
    """Emoji spamı kontrolü."""
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # symbols & pictographs
        "\U0001F680-\U0001F6FF"  # transport & map symbols
        "\U0001F1E0-\U0001F1FF"  # flags
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "]+", flags=re.UNICODE
    )
    emojis = emoji_pattern.findall(text)
    total_emojis = sum(len(e) for e in emojis)
    return total_emojis > MAX_EMOJI_COUNT

def is_caps_spam(text: str) -> bool:
    """BÜYÜK HARF spamı kontrolü."""
    if len(text) < 10:
        return False
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return False
    caps = [c for c in letters if c.isupper()]
    return len(caps) / len(letters) > MAX_CAPS_RATIO

def contains_invite_link(text: str) -> bool:
    """Davet linki var mı?"""
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
    """Diğer platform linkleri var mı?"""
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
    """Şüpheli URL kontrolü."""
    # Kısaltılmış URL'ler
    shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link']
    for s in shorteners:
        if s in text.lower():
            return True

    # Phishing anahtar kelimeleri
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
    """Dolandırıcılık içeriği tespiti."""
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
    """Taciz/zorbalık/nefret söylemi tespiti."""
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
# RİSK SKORU HESAPLAMA
# ───────────────────────────────

def calculate_risk_score(text: str, user_id: int, chat_id: int) -> tuple[int, List[str], str]:
    """Mesajın risk skorunu hesapla."""
    score = 0
    reasons = []
    category = "Güvenli"

    # Küfür kontrolü (+40)
    has_swear, swear_word = contains_swear(text)
    if has_swear:
        score += 40
        reasons.append(f"Küfür/hakaret: {swear_word}")
        category = "Küfür"

    # Spam kontrolü (+20)
    if is_emoji_spam(text):
        score += 20
        reasons.append("Emoji spamı")
        if category == "Güvenli":
            category = "Spam"

    if is_caps_spam(text):
        score += 15
        reasons.append("Büyük harf spamı")
        if category == "Güvenli":
            category = "Spam"

    # Reklam kontrolü (+30)
    if contains_invite_link(text):
        score += 30
        reasons.append("Telegram davet linki")
        category = "Reklam"

    if contains_external_link(text):
        score += 20
        reasons.append("Harici platform reklamı")
        if category == "Güvenli":
            category = "Reklam"

    # Dolandırıcılık kontrolü (+50)
    if is_scam(text):
        score += 50
        reasons.append("Dolandırıcılık şüphesi")
        category = "Dolandırıcılık"

    # Şüpheli link (+25)
    if is_suspicious_url(text):
        score += 25
        reasons.append("Şüpheli link")
        if category == "Güvenli":
            category = "Şüpheli"

    # Taciz/nefret söylemi (+45)
    is_harass, harass_type = is_harassment(text)
    if is_harass:
        score += 45
        reasons.append(f"Taciz/nefret söylemi: {harass_type}")
        if harass_type == "tehdit":
            category = "Tehdit"
        else:
            category = "Nefret Söylemi"

    # Flood kontrolü (+20)
    if is_flood(chat_id, user_id, text):
        score += 20
        reasons.append("Flood")
        if category == "Güvenli":
            category = "Spam"

    # Zincir mesaj kontrolü (+10)
    if text.count('\n') > 5 or len(text) > MAX_MSG_LENGTH:
        score += 10
        reasons.append("Uzun/zincir mesaj")

    # Yeni üye link paylaşımı (+15)
    if chat_id in new_members and user_id in new_members[chat_id]:
        if 'http' in text.lower() or 'www' in text.lower() or contains_invite_link(text):
            score += 15
            reasons.append("Yeni üye link paylaşımı")

    return min(score, 100), reasons, category

# ───────────────────────────────
# CEZA SİSTEMİ
# ───────────────────────────────

async def apply_mute(update: Update, context: ContextTypes.DEFAULT_TYPE, 
                     user_id: int, duration: int, reason: str):
    """Kullanıcıyı sustur."""
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

        # Log
        await log_action(context, chat_id, "MUTE", user_id, reason, duration)

    except Exception as e:
        logging.error(f"Mute error: {e}")

async def apply_ban(update: Update, context: ContextTypes.DEFAULT_TYPE,
                    user_id: int, reason: str, permanent: bool = True):
    """Kullanıcıyı banla."""
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
    """Kullanıcıyı uyar."""
    chat_id = update.effective_chat.id
    user_violations[chat_id][user_id] += 1
    count = user_violations[chat_id][user_id]

    # Otomatik ceza
    if count == 1:
        msg = f"⚠️ Uyarı {count}/5: {reason}"
    elif count == 2:
        await apply_mute(update, context, user_id, MUTE_10MIN, reason)
        msg = f"🔇 10 dakika susturuldu ({count}/5 ihlal): {reason}"
    elif count == 3:
        await apply_mute(update, context, user_id, MUTE_1HOUR, reason)
        msg = f"🔇 1 saat susturuldu ({count}/5 ihlal): {reason}"
    elif count == 4:
        await apply_mute(update, context, user_id, MUTE_1DAY, reason)
        msg = f"🔇 1 gün susturuldu ({count}/5 ihlal): {reason}"
    else:
        await apply_ban(update, context, user_id, reason)
        msg = f"⛔ Kalıcı ban ({count} ihlal): {reason}"
        user_violations[chat_id][user_id] = 0

    try:
        await context.bot.send_message(chat_id=chat_id, text=msg)
    except Exception as e:
        logging.error(f"Warn message error: {e}")

    await log_action(context, chat_id, "WARN", user_id, reason, count)

async def log_action(context: ContextTypes.DEFAULT_TYPE, chat_id: int, 
                     action: str, user_id: int, reason: str, extra=None):
    """Moderasyon işlemini kaydet."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "action": action,
        "chat_id": chat_id,
        "user_id": user_id,
        "reason": reason,
        "extra": extra
    }

    # Dosyaya kaydet
    logs = load_json("moderation_logs.json")
    logs.setdefault(str(chat_id), []).append(log_entry)
    save_json("moderation_logs.json", logs)

    # Log kanalına gönder
    if LOG_CHANNEL:
        try:
            extra_str = f" | Ek: {extra}" if extra else ""
            text = (f"🛡️ NORD Guard Log\n"
                    f"Eylem: {action}\n"
                    f"Kullanıcı: {user_id}\n"
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
    """Kullanıcı admin mi?"""
    try:
        member = await context.bot.get_chat_member(chat_id, user_id)
        return isinstance(member, (ChatMemberOwner, ChatMemberAdministrator))
    except Exception:
        return False

async def is_bot_admin(chat_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """Bot admin yetkisine sahip mi?"""
    try:
        bot_member = await context.bot.get_chat_member(chat_id, context.bot.id)
        return isinstance(bot_member, (ChatMemberOwner, ChatMemberAdministrator))
    except Exception:
        return False

# ───────────────────────────────
# CAPTCHA SİSTEMİ
# ───────────────────────────────

import random
import string

def generate_captcha() -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

async def send_captcha(update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int):
    """Yeni üyeye captcha gönder."""
    chat_id = update.effective_chat.id
    code = generate_captcha()
    user_captcha[(chat_id, user_id)] = code

    keyboard = [
        [InlineKeyboardButton(code, callback_data=f"captcha_{user_id}_{code}")]
    ]
    # Yanlış seçenekler
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
        text=f"🔐 Hoş geldin! Spam koruması için doğru kodu seç:\n"
             f"Doğru kodu bul ve grupta konuşmaya başla.",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

    # Yeni üyeyi kısıtla
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
    """Tüm mesajları analiz et ve müdahale et."""
    if not update.message or not update.effective_chat:
        return

    chat_id = update.effective_chat.id
    user_id = update.message.from_user.id
    text = update.message.text or update.message.caption or ""

    # Admin mesajlarını asla silme
    if await is_admin(chat_id, user_id, context):
        return

    # Bot admin mi kontrol et
    if not await is_bot_admin(chat_id, context):
        return

    # Modül kontrolü
    if not module_status[chat_id].get("guard", True):
        return

    # Raid modu kontrolü
    if raid_mode[chat_id]:
        # Raid modunda yeni üyeler susturulsun
        if user_id in new_members.get(chat_id, set()):
            await update.message.delete()
            return

    # Risk analizi
    score, reasons, category = calculate_risk_score(text, user_id, chat_id)

    # Ağır ihlaller -> Direkt ban
    if category in ["Dolandırıcılık", "Tehdit", "Nefret Söylemi", "Zararlı İçerik"]:
        if score >= RISK_HIGH:
            await update.message.delete()
            await apply_ban(update, context, user_id, f"{category}: {', '.join(reasons)}")
            return

    # Kritik risk -> Ban
    if score >= RISK_CRITICAL:
        await update.message.delete()
        await apply_ban(update, context, user_id, f"Kritik risk ({score}): {', '.join(reasons)}")
        return

    # Yüksek risk -> Mesaj sil + susturma
    if score >= RISK_HIGH:
        await update.message.delete()
        await apply_mute(update, context, user_id, MUTE_1HOUR, f"Yüksek risk ({score}): {', '.join(reasons)}")
        await context.bot.send_message(
            chat_id=chat_id,
            text=f"🛡️ Yüksek risk mesaj silindi.\nKullanıcı: {update.message.from_user.mention_html()}\nSebep: {', '.join(reasons)}"
        )
        return

    # Orta risk -> Mesaj sil + uyarı
    if score >= RISK_MEDIUM:
        await update.message.delete()
        await apply_warn(update, context, user_id, f"Orta risk ({score}): {', '.join(reasons)}")
        return

    # Düşük risk -> Uyarı
    if score >= RISK_LOW:
        # Sadece ilk kez uyarı
        if user_violations[chat_id][user_id] == 0:
            await apply_warn(update, context, user_id, f"Düşük risk ({score}): {', '.join(reasons)}")
        return

# ───────────────────────────────
# YENİ ÜYE İŞLEYİCİ
# ───────────────────────────────

async def new_member_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Yeni üye katılışını işle."""
    if not update.message or not update.effective_chat:
        return

    chat_id = update.effective_chat.id

    for member in update.message.new_chat_members:
        user_id = member.id

        # Bot kendisi mi?
        if user_id == context.bot.id:
            continue

        # Raid tespiti
        now = time.time()
        join_history[chat_id].append(now)

        # Son 60 saniyede 5+ üye = raid
        recent_joins = [t for t in join_history[chat_id] if now - t < 60]
        if len(recent_joins) >= 5:
            raid_mode[chat_id] = True
            # Sohbeti yavaş moda al
            try:
                await context.bot.set_chat_slow_mode(chat_id, 30)
            except Exception:
                pass
            # Moderatörleri uyar
            await context.bot.send_message(
                chat_id=chat_id,
                text="🚨 RAID ALARMI! Çok sayıda üye girişi tespit edildi.\n"
                     "Sohbet yavaş moda alındı. Yeni üye girişleri sınırlandı."
            )

        # Yeni üye kaydet
        new_members[chat_id].add(user_id)

        # Captcha gönder
        await send_captcha(update, context, user_id)

# ───────────────────────────────
# CAPTCHA CALLBACK
# ───────────────────────────────

async def captcha_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Captcha doğrulama."""
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

    # Başkası için basma kontrolü
    if user_id != target_user_id:
        await query.edit_message_text("❌ Bu captcha sana ait değil!")
        return

    correct_code = user_captcha.get((chat_id, user_id))

    if code == correct_code:
        # Doğru! Kısıtlamayı kaldır
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
            await query.edit_message_text("✅ Doğrulama başarılı! Konuşmaya başlayabilirsin.")
        except Exception as e:
            logging.error(f"Captcha unrestrict error: {e}")
    else:
        await query.edit_message_text("❌ Yanlış kod! Lütfen tekrar dene.")

# ───────────────────────────────
# ADMIN KOMUTLARI
# ───────────────────────────────

async def cmd_guard_on(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Korumayı aç."""
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    module_status[update.effective_chat.id]["guard"] = True
    await update.message.reply_text("✅ NORD Guard aktif!")

async def cmd_guard_off(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Korumayı kapat."""
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    module_status[update.effective_chat.id]["guard"] = False
    await update.message.reply_text("⛔ NORD Guard devre dışı.")

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
    await update.message.reply_text("🛡️ Maksimum koruma aktif! Tüm modüller açık.")

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
    await update.message.reply_text("⚙️ Özel koruma modu. Modülleri manuel aç/kapat.")

async def cmd_mute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("Bir mesaja yanıt vererek kullan.")
        return
    target = update.message.reply_to_message.from_user.id
    duration = 3600  # default 1 saat
    if context.args:
        try:
            duration = int(context.args[0]) * 60
        except ValueError:
            pass
    await apply_mute(update, context, target, duration, "Admin mute")
    await update.message.reply_text(f"🔇 Kullanıcı susturuldu ({duration//60} dk).")

async def cmd_unmute(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("Bir mesaja yanıt vererek kullan.")
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
        await update.message.reply_text("🔊 Kullanıcı susturması kaldırıldı.")
    except Exception as e:
        await update.message.reply_text(f"Hata: {e}")

async def cmd_ban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("Bir mesaja yanıt vererek kullan.")
        return
    target = update.message.reply_to_message.from_user.id
    await apply_ban(update, context, target, "Admin ban")
    await update.message.reply_text("⛔ Kullanıcı banlandı.")

async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not context.args:
        await update.message.reply_text("Kullanıcı ID'si gir: /unban 123456789")
        return
    try:
        target = int(context.args[0])
        await context.bot.unban_chat_member(update.effective_chat.id, target)
        await update.message.reply_text("✅ Ban kaldırıldı.")
    except Exception as e:
        await update.message.reply_text(f"Hata: {e}")

async def cmd_warn(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("Bir mesaja yanıt vererek kullan.")
        return
    target = update.message.reply_to_message.from_user.id
    reason = " ".join(context.args) if context.args else "Admin uyarısı"
    await apply_warn(update, context, target, reason)

async def cmd_clearwarns(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    if not update.message.reply_to_message:
        await update.message.reply_text("Bir mesaja yanıt vererek kullan.")
        return
    target = update.message.reply_to_message.from_user.id
    chat_id = update.effective_chat.id
    user_violations[chat_id][target] = 0
    await update.message.reply_text("🧹 Kullanıcı uyarıları temizlendi.")

async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    chat_id = update.effective_chat.id
    logs = load_json("moderation_logs.json")
    chat_logs = logs.get(str(chat_id), [])

    actions = Counter([log["action"] for log in chat_logs])
    stats_text = "📊 NORD Guard İstatistikleri\n\n"
    for action, count in actions.most_common():
        stats_text += f"{action}: {count}\n"
    stats_text += f"\nToplam: {len(chat_logs)} işlem"

    await update.message.reply_text(stats_text)

async def cmd_security(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await is_admin(update.effective_chat.id, update.effective_user.id, context):
        return
    chat_id = update.effective_chat.id
    status = module_status[chat_id]
    level = protection_level[chat_id]
    raid = "🚨 AKTİF" if raid_mode[chat_id] else "✅ Pasif"

    text = (f"🛡️ NORD Guard Güvenlik Durumu\n\n"
            f"Koruma Seviyesi: {level.upper()}\n"
            f"Raid Modu: {raid}\n\n"
            f"Modüller:\n"
            f"  Guard: {'✅' if status.get('guard') else '❌'}\n"
            f"  Anti-Spam: {'✅' if status.get('antispam') else '❌'}\n"
            f"  Anti-Flood: {'✅' if status.get('antiflood') else '❌'}\n"
            f"  Anti-Link: {'✅' if status.get('antilink') else '❌'}\n"
            f"  Anti-Raid: {'✅' if status.get('antiraid') else '❌'}\n")

    await update.message.reply_text(text)

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ NORD Guard\n"
        "Üst düzey Telegram güvenlik ve moderasyon botu.\n\n"
        "Beni gruba admin olarak ekle ve /protection max yaz."
    )

async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = """
🛡️ NORD Guard Komutları

Admin Komutları:
/guard on/off - Koruma aç/kapat
/antispam on - Spam koruması
/antiflood on - Flood koruması
/antilink on - Link koruması
/antiraid on - Raid koruması
/protection max - Maksimum koruma
/protection normal - Normal koruma
/protection custom - Özel koruma

Moderasyon:
/mute [dakika] - Sustur (yanıtla)
/unmute - Susturma kaldır (yanıtla)
/ban - Ban (yanıtla)
/unban <id> - Ban kaldır
/warn [sebep] - Uyar (yanıtla)
/clearwarns - Uyarıları temizle (yanıtla)

Bilgi:
/stats - İstatistikler
/security - Güvenlik durumu

Kurulum:
1. Beni gruba ekle
2. Admin yetkisi ver (mesaj silme, üye banlama, mesaj sabitleme)
3. /protection max yaz
    """
    await update.message.reply_text(help_text)

# ───────────────────────────────
# HATA YAKALAMA
# ───────────────────────────────

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logging.error(f"Update {update} caused error {context.error}")

# ───────────────────────────────
# ANA FONKSİYON
# ───────────────────────────────

def main():
    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO
    )

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

    # Callback
    application.add_handler(CallbackQueryHandler(captcha_callback, pattern="^captcha_"))

    # Mesajlar
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))
    application.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, new_member_handler))

    # Hata
    application.add_error_handler(error_handler)

    print("🛡️ NORD Guard başlatılıyor...")
    application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
