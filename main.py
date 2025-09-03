#!/usr/bin/env python3
from stable_baselines3 import PPO
import shutil
from pathlib import Path
import numpy as np
import json
import sqlite3
import time
import os
import socket
import logging
import asyncio
from dateutil import parser as dateparser
from threading import Thread, Lock, RLock
from datetime import datetime, timedelta
import subprocess
from queue import Queue
import signal
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)
from dataset_extension import init_dataset, append_dataset
from dataset_extension import klasifikasi_jenis_serangan, append_dataset
from training import make_env, train_ppo
import pandas as pd  # Import pandas yang diperlukan

# ========== LOGGING CONFIG ==========
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ========== GLOBAL STATE ==========
shutdown_flag = False
config = None
application = None
bot = None
processed_events = {}
current_log_file = None
LOCAL_IP = None
drl_analyzer = None
db_lock = Lock()
ip_lock = RLock()

# ========== CONFIGURATION ==========
CONFIG_DEFAULTS = {
    "token": "",
    "chat_id": "",
    "suricata_log_path": "/var/log/suricata/eve-%Y-%m-%d.json",
    "drl_model_path": "ppo_suricata_latest.zip",
    "pool_size": 8,
    "timeout": 30,
    "read_timeout": 30,
    "write_timeout": 30,
    "connect_timeout": 30,
    "cooldown": 1,
    "event_cooldown": 60,
    "log_rotation_check_interval": 60,
    "whitelist_ips": ["127.0.0.1", "192.168.1.1"],
    "min_confidence": 0.7,
    "monitor_direction": "inbound"
}

SIGNATURE_KLASIFIKASI = {
    "scan": ["scan", "portscan", "nmap", "masscan"],
    "dos": ["dos", "denial of service", "flood"],
    "exploit": ["exploit", "code execution", "overflow", "adobe", "shellcode"],
    "brute": ["brute", "dictionary", "guess"],
    "malware": ["malware", "trojan", "virus", "backdoor", "ransomware"],
    "botnet": ["botnet", "command and control", "c2", "irc"],
    "web": ["web attack", "xss", "sql injection", "lfi", "rfi", "csrf"],
    "info": ["info", "suspicious", "generic", "policy"]
}

IGNORED_SIGNATURES = [
    "SURICATA QUIC failed decrypt",
    # tambahkan signature lain yang mau dianggap benign
]

# ========== UTILITY FUNCTIONS ==========
def load_config():
    global config
    config_path = "bot_config.json"
    try:
        if not os.path.exists(config_path):
            logger.error("Config file not found, creating default config")
            with open(config_path, 'w') as f:
                json.dump(CONFIG_DEFAULTS, f, indent=2)
            config = CONFIG_DEFAULTS
        else:
            with open(config_path) as f:
                config = json.load(f)
        
        for key, value in CONFIG_DEFAULTS.items():
            if key not in config:
                config[key] = value
                logger.warning(f"Using default value for missing config: {key}={value}")
                
        if not config.get("token"):
            raise ValueError("Telegram bot token is required")
        if not config.get("chat_id"):
            raise ValueError("Chat ID is required")
            
        return config
    except Exception as e:
        logger.critical(f"Failed to load config: {e}")
        exit(1)

def get_local_ip():
    global LOCAL_IP
    if not LOCAL_IP:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            LOCAL_IP = s.getsockname()[0]
        except Exception:
            LOCAL_IP = '127.0.0.1'
        finally:
            s.close()
    return LOCAL_IP

def get_latest_suricata_log():
    """Get today's Suricata log file"""
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        log_path = f"/var/log/suricata/eve-{today}.json"
        
        if os.path.exists(log_path):
            return log_path
        
        logger.warning(f"Log file {log_path} not found, checking alternatives...")
        
        default_path = "/var/log/suricata/eve.json"
        if os.path.exists(default_path):
            logger.info(f"Using fallback log file: {default_path}")
            return default_path
            
        raise FileNotFoundError(f"No Suricata log file found at {log_path} or {default_path}")
    except Exception as e:
        logger.error(f"Error finding log file: {e}")
        return None

def klasifikasi_jenis_serangan(signature: str) -> str:
    signature_lower = signature.lower()
    for kategori, keywords in SIGNATURE_KLASIFIKASI.items():
        if any(keyword in signature_lower for keyword in keywords):
            return kategori.upper()
    return "UNKNOWN"

# ========== DATABASE FUNCTIONS ==========
def init_db():
    with db_lock:
        conn = sqlite3.connect("anomali.db", check_same_thread=False)
        c = conn.cursor()
        
        # Create log table with direction column
        c.execute("""
            CREATE TABLE IF NOT EXISTS log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                signature TEXT,
                status TEXT,
                action_by TEXT,
                confidence REAL,
                log_file TEXT,
                jenis_serangan TEXT,
                direction TEXT
            )
        """)
        
        # Add direction column if not exists
        c.execute("PRAGMA table_info(log)")
        columns = [col[1] for col in c.fetchall()]
        if 'direction' not in columns:
            c.execute("ALTER TABLE log ADD COLUMN direction TEXT")
            logger.info("Added direction column to log table")
        
        c.execute("""
            CREATE TABLE IF NOT EXISTS blocked_ips (
                ip TEXT PRIMARY KEY,
                timestamp TEXT,
                reason TEXT,
                confidence REAL,
                unblock_time TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        logger.info("Database initialized")

def simpan_log(timestamp, src_ip, dst_ip, signature, status, action_by="system", confidence=None, direction="inbound"):
    jenis_serangan = klasifikasi_jenis_serangan(signature)
    
    with db_lock:
        conn = sqlite3.connect("anomali.db", check_same_thread=False)
        c = conn.cursor()
        
        try:
            c.execute("""
                INSERT INTO log 
                (timestamp, src_ip, dst_ip, signature, status, action_by, confidence, log_file, jenis_serangan, direction) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, src_ip, dst_ip, signature, status, action_by, confidence, current_log_file, jenis_serangan, direction))
            conn.commit()
            logger.debug(f"Logged event: {src_ip} -> {dst_ip} ({signature}) Direction: {direction}")
        except Exception as e:
            logger.error(f"Error saving log: {e}")
        finally:
            conn.close()

# ========== IP MANAGEMENT ==========
def blokir_ip(ip, metode="manual", confidence=None, reason=""):
    global config
    
    if ip in config["whitelist_ips"] or ip == LOCAL_IP:
        logger.info(f"Skipping whitelisted IP: {ip}")
        return False
    
    with ip_lock:
        try:
            conn = sqlite3.connect("anomali.db", check_same_thread=False)
            c = conn.cursor()
            c.execute("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,))
            if c.fetchone():
                conn.close()
                return False
            
            # Block incoming traffic from this IP
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            
            unblock_time = (datetime.now() + timedelta(hours=24)).isoformat()
            c.execute("""
                INSERT INTO blocked_ips 
                (ip, timestamp, reason, confidence, unblock_time) 
                VALUES (?, ?, ?, ?, ?)
            """, (ip, datetime.now().isoformat(), reason, confidence, unblock_time))
            
            conn.commit()
            logger.info(f"[✓] IP {ip} blocked ({metode}) - {reason}")
            return True
        except Exception as e:
            logger.error(f"[!] Failed to block IP {ip}: {e}")
            return False
        finally:
            conn.close()

def izinkan_ip(ip):
    with ip_lock:
        conn = None
        try:
            # Hapus rule iptables, tapi tangani jika rule tidak ada
            try:
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            except subprocess.CalledProcessError as e:
                logger.warning(f"No existing iptables rule to delete for {ip}: {e}")

            # Buka koneksi DB hanya setelah iptables selesai
            conn = sqlite3.connect("anomali.db", check_same_thread=False)
            c = conn.cursor()
            c.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
            conn.commit()
            logger.info(f"[✓] IP {ip} unblocked")
            return True

        except Exception as e:
            logger.error(f"[!] Failed to unblock IP {ip}: {e}")
            return False

        finally:
            # Tutup DB hanya jika sudah berhasil dibuat
            if conn:
                conn.close()

# ========== DRL ANALYZER ==========
class DRLAnalyzer:
    def __init__(self, model_path):
        try:
            self.model = PPO.load(model_path)
            logger.info(f"DRL model loaded from {model_path}")
            self.expected_features = 15
        except Exception as e:
            logger.critical(f"Failed to load DRL model: {e}")
            raise
    
    def extract_features_from_pcap(pcap_path):
        # contoh minimal: hitung jumlah paket, total bytes — gunakan pyshark atau scapy untuk detail
        try:
            import pyshark
            cap = pyshark.FileCapture(pcap_path, keep_packets=False)
            pkt_count = 0
            total_bytes = 0
            for pkt in cap:
                pkt_count += 1
                if hasattr(pkt, 'length'):
                    try:
                        total_bytes += int(pkt.length)
                    except:
                        pass
            cap.close()
            return {'pkt_count': pkt_count, 'total_bytes': total_bytes}
        except Exception as e:
            logger.debug(f"pyshark not available or error reading pcap: {e}")
            return {}
    
    def preprocess_event(self, event):
        try:
            flow = event.get('flow', {})
            # Pastikan timestamp ada dan dalam format yang benar
            ts_str = event.get('timestamp')
            if ts_str:
                ts = datetime.fromisoformat(ts_str)
            else:
                ts = datetime.now()
            
            features = [
                float(hash(event.get('src_ip', ''))) % 1000,
                float(hash(event.get('dst_ip', ''))) % 1000,
                float(event.get('src_port', 0)),
                float(event.get('dest_port', 0)),
                1.0 if event.get('proto', '').lower() == 'tcp' else 0.0,
                1.0 if event.get('proto', '').lower() == 'udp' else 0.0,
                float(flow.get('pkts_toserver', 0)),
                float(flow.get('pkts_toclient', 0)),
                float(flow.get('bytes_toserver', 0)),
                float(flow.get('bytes_toclient', 0)),
                float(ts.hour),
                float(ts.weekday()),
                float(event.get('alert', {}).get('severity', 1)),
                float(len(event.get('signature', ''))),
                float(hash(event.get('signature', ''))) % 1000
            ]
            
            if len(features) < self.expected_features:
                features += [0.0] * (self.expected_features - len(features))
            elif len(features) > self.expected_features:
                features = features[:self.expected_features]
                
            return np.array(features, dtype=np.float32).reshape(1, -1)
        except Exception as e:
            logger.error(f"Error preprocessing event: {e}")
            return None
    
    def predict(self, event):
        try:
            obs = self.preprocess_event(event)
            if obs is None:
                return 0, 0.0
                
            action, _ = self.model.predict(obs)
            confidence = 0.8  # Default confidence
            return int(action[0]), float(confidence)
        except Exception as e:
            logger.error(f"[!] DRL prediction error: {e}")
            return 0, 0.0

# ========== TELEGRAM BOT FUNCTIONS ==========
def convert_to_training_format(event, action, confidence):
    """Convert Suricata event to training dataset format"""
    flow = event.get('flow', {})
    return {
        'timestamp': event['timestamp'],
        'src_ip': event['src_ip'],
        'dst_ip': event.get('dst_ip', ''),
        'src_port': event.get('src_port', 0),
        'dst_port': event.get('dest_port', 0),
        'proto': event.get('proto', 'unknown'),
        'signature': event['signature'],
        'fwd_pkts_tot': flow.get('pkts_toserver', 0),
        'bwd_pkts_tot': flow.get('pkts_toclient', 0),
        'fwd_data_pkts_tot': flow.get('bytes_toserver', 0),
        'bwd_data_pkts_tot': flow.get('bytes_toclient', 0),
        'action': action,
        'confidence': confidence
    }

async def send_welcome_message():
    try:
        keyboard = [
            [InlineKeyboardButton("🔄 Update System", callback_data="update_system")],
            [InlineKeyboardButton("🚀 Start Monitoring", callback_data="start_bot")],
            #[InlineKeyboardButton("📊 System Status", callback_data="status_bot")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await bot.send_message(
            chat_id=config["chat_id"],
            text=(
                "🛡️ *Inbound Anomaly Detection Bot* is now active!\n\n"
                "🔄 Tekan *Update System* untuk retrain model,\n"
                "atau langsung *Start Monitoring*."
            ),
            parse_mode="Markdown",
            reply_markup=reply_markup
        )
    except Exception as e:
        logger.error(f"Failed to send welcome message: {e}")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Update {update} caused error {context.error}")
    try:
        await context.bot.send_message(
            chat_id=update.effective_chat.id if update else config["chat_id"],
            text="⚠️ An error occurred. Please try again later."
        )
    except Exception as e:
        logger.error(f"Error sending error message: {e}")

async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    data = query.data
    await query.answer()
    try:
        if data == "update_system":
            await run_retraining(update, context)
        elif data == "start_bot":
            await start(update, context)
        elif data == "status_bot":
            await cek_status(update, context)
        elif data == "list_blocked":
            await list_blocked_ips(update, context)
        elif data.startswith("blokir_"):
            ip = data.split("_", 1)[1]
            # Jika pemblokiran berhasil, refresh daftar blocked IP (jika pengguna sedang melihat daftar)
            if blokir_ip(ip):
                # Jika callback berasal dari daftar blocked, tampilkan ulang daftar
                await list_blocked_ips(update, context)
            else:
                await query.edit_message_text(f"❌ Gagal memblock IP `{ip}`. Periksa log.")
        elif data.startswith("izin_"):
            ip = data.split("_", 1)[1]
            # Setelah berhasil unblock, panggil ulang list_blocked_ips agar daftar ter-refresh
            if izinkan_ip(ip):
                # Tampilkan ulang daftar blocked IP — IP yang di-unblock akan hilang,
                # sementara IP lain tetap tampil sampai semua di-unblock atau user tekan Back.
                await list_blocked_ips(update, context)
            else:
                await query.edit_message_text(f"❌ Gagal unblock IP `{ip}`. Periksa log.")
    except Exception as e:
        logger.error(f"Error in callback handler: {e}")
        await error_handler(update, context)


async def run_retraining(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.edit_message_text("⏳ Retraining model… Mohon tunggu sebentar.")

    try:
        # 1. Baca dataset dengan header otomatis
        df = pd.read_csv("dataset_clean.csv")

        # 2. Parse kolom timestamp (termasuk offset zona waktu)
        df['timestamp'] = pd.to_datetime(
            df['timestamp'],
            format="%Y-%m-%dT%H:%M:%S.%f%z",
            errors='coerce'
        )

        # 3. Drop baris tanpa timestamp valid
        df = df.dropna(subset=['timestamp']).reset_index(drop=True)

        # 4. Pastikan tidak empty
        if df.empty:
            await query.edit_message_text(
                "⚠️ Retraining dibatalkan: tidak ada data dengan timestamp valid."
            )
            return

        # 5. Pilih kolom untuk training
        df_train = df[[
            'timestamp', 'src_ip', 'dst_ip',
            'src_port', 'dst_port', 'proto',
            'fwd_pkts_tot', 'bwd_pkts_tot',
            'fwd_data_pkts_tot', 'bwd_data_pkts_tot',
            'signature', 'action'
        ]]

        # 6. Build environment & latih model
        env = make_env(df_train)
        new_model = train_ppo(env)

        # 7. Simpan model terbaru
        new_path = "ppo_suricata_latest.zip"
        new_model.save(new_path)
        drl_analyzer.model = new_model
        config["drl_model_path"] = new_path

        # 8. Tampilkan tombol Start
        keyboard = [[InlineKeyboardButton("🚀 Start Monitoring", callback_data="start_bot")]]
        await query.edit_message_text(
            text=f"✅ Retraining selesai, model disimpan sebagai `{new_path}`.\nSilakan tekan Start Monitoring.",
            reply_markup=InlineKeyboardMarkup(keyboard),
        )

    except Exception as e:
        logger.error(f"Retraining failed: {e}")
        await query.edit_message_text("❌ Retraining gagal. Lihat log untuk detail.")


    except Exception as e:
        logger.error(f"Retraining failed: {e}")
        await query.edit_message_text("❌ Retraining gagal. Lihat log untuk detail.")


    except Exception as e:
        logger.error(f"Retraining failed: {e}")
        await query.edit_message_text("❌ Retraining gagal. Lihat log untuk detail.")
        
    except Exception as e:
        logger.error(f"Retraining failed: {e}")
        await query.edit_message_text("❌ Retraining gagal. Lihat log untuk detail.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        keyboard = [
            [InlineKeyboardButton("📊 Status", callback_data="status_bot")],
            [InlineKeyboardButton("🛡️ Blocked IPs", callback_data="list_blocked")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        message = (
            f"🛡️ **Inbound Traffic Monitoring**\n"
            f"🖥️ Local IP: `{LOCAL_IP}`\n\n"
            "Monitoring all INBOUND network activities."
        )
        
        if hasattr(update, 'callback_query'):
            await update.callback_query.edit_message_text(
                text=message,
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=message,
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
    except Exception as e:
        logger.error(f"Error in start handler: {e}")
        await error_handler(update, context)

async def cek_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        conn = sqlite3.connect("anomali.db", check_same_thread=False)
        c = conn.cursor()
        
        stats = "• No attack data available"
        blocked_count = 0
        
        try:
            c.execute("SELECT jenis_serangan, COUNT(*) FROM log GROUP BY jenis_serangan")
            stats = "\n".join([f"• {row[0]}: {row[1]} events" for row in c.fetchall()])
            
            c.execute("SELECT COUNT(*) FROM blocked_ips")
            blocked_result = c.fetchone()
            blocked_count = blocked_result[0] if blocked_result else 0
        except sqlite3.Error as e:
            logger.error(f"Database error in cek_status: {e}")
            stats = "• Error retrieving statistics"
            blocked_count = "N/A"
        
        status_msg = (
            f"📊 **System Status**\n\n"
            f"🔒 Blocked IPs: {blocked_count}\n"
            f"📈 Event Statistics:\n{stats}"
        )
        
        keyboard = [[InlineKeyboardButton("🔙 Back", callback_data="start_bot")]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if hasattr(update, 'callback_query'):
            await update.callback_query.edit_message_text(
                text=status_msg,
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=status_msg,
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
    except Exception as e:
        logger.error(f"Error in cek_status: {e}")
        await error_handler(update, context)
    finally:
        if 'conn' in locals():
            conn.close()

async def list_blocked_ips(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        conn = sqlite3.connect("anomali.db", check_same_thread=False)
        c = conn.cursor()
        
        c.execute("SELECT ip, reason, timestamp FROM blocked_ips")
        blocked_ips = c.fetchall()
        
        keyboard = []  # Initialize keyboard
        
        if not blocked_ips:
            message = "🔒 No blocked IPs found"
        else:
            message = "🛡️ Blocked IPs:\n\n"
            for ip, reason, timestamp in blocked_ips:
                message += f"• `{ip}` - {reason} ({timestamp})\n"
                keyboard.append([InlineKeyboardButton(f"✅ Unblock {ip}", callback_data=f"izin_{ip}")])
        
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="start_bot")])
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if hasattr(update, 'callback_query'):
            await update.callback_query.edit_message_text(
                text=message,
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=message,
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )
    except Exception as e:
        logger.error(f"Error in list_blocked_ips: {e}")
        await error_handler(update, context)
    finally:
        if 'conn' in locals():
            conn.close()

async def kirim_notifikasi(anomali_data):
    try:
        # Validasi minimal
        sig = (anomali_data.get("signature") or "").strip()
        src_ip = anomali_data.get("src_ip")

        # Jika signature termasuk noisy/benign, simpan saja ke dataset dan DB tapi jangan kirim notifikasi
        if sig and any(ignored.lower() in sig.lower() for ignored in IGNORED_SIGNATURES):
            logger.info(f"Ignored noisy signature (benign for notif): {sig} from {src_ip}")

            # Simpan ke DB sebagai ignored/benign — supaya histori tetap tercatat
            simpan_log(
                anomali_data.get('timestamp', datetime.now().isoformat()),
                src_ip,
                anomali_data.get('dst_ip', ''),
                sig,
                status="ignored",
                action_by="system",
                confidence=0.0,
                direction=anomali_data.get('direction', 'inbound')
            )

            # Tambahkan ke dataset untuk DRL dengan label benign (action=0)
            try:
                # convert_to_training_format memastikan format yang sesuai untuk append_dataset
                train_row = convert_to_training_format(anomali_data, action=0, confidence=0.0)
                append_dataset(train_row, 0, 0.0)
                logger.debug(f"Appended ignored event to dataset: {src_ip} - {sig}")
            except Exception as e:
                logger.error(f"Failed to append ignored event to dataset: {e}")

            # tidak mengirim notifikasi Telegram
            return

        # Jika bukan signature yang di-ignore: proses normal
        if not anomali_data.get("src_ip") or not sig:
            logger.warning("Incomplete alert data, skipping notification")
            return

        event_id = f"{anomali_data['src_ip']}_{sig}"

        if event_id in processed_events:
            if time.time() - processed_events[event_id] < config.get("event_cooldown", 60):
                logger.debug(f"Skipping duplicate event: {event_id}")
                return

        processed_events[event_id] = time.time()

        # Prediksi DRL dan simpan ke dataset (sebelum/atau sesudah tindakan)
        action, confidence = drl_analyzer.predict(anomali_data)

        try:
            train_row = convert_to_training_format(anomali_data, action, confidence)
            append_dataset(train_row, action, confidence)
        except Exception as e:
            logger.error(f"Failed to append event to dataset: {e}")

        jenis_serangan = klasifikasi_jenis_serangan(sig)
        logger.info(f"New alert: {jenis_serangan} from {anomali_data['src_ip']} (confidence: {confidence:.2f})")

        # AUTO-BLOCK jika DRL menyuruh dan confidence cukup
        if action > 0 and confidence >= config.get("min_confidence", 0.7):
            reason = f"{jenis_serangan} attack detected (confidence: {confidence:.2f})"
            if blokir_ip(anomali_data['src_ip'], metode="DRL", confidence=confidence, reason=reason):
                message = (
                    f"🚨 **INBOUND THREAT DETECTED & BLOCKED**\n\n"
                    f"🕒 {anomali_data['timestamp']}\n"
                    f"🔍 Signature: `{sig}`\n"
                    f"📍 Attacker IP: `{anomali_data['src_ip']}`\n"
                    f"🎯 Target IP: `{anomali_data.get('dst_ip', LOCAL_IP)}`\n"
                    f"📊 Confidence: {confidence:.2f}\n"
                    f"🛡️ IP automatically blocked by DRL system"
                )

                keyboard = [
                    [InlineKeyboardButton("✅ Unblock IP", callback_data=f"izin_{anomali_data['src_ip']}")],
                    [InlineKeyboardButton("📊 Status", callback_data="status_bot")]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)

                await bot.send_message(
                    chat_id=config["chat_id"],
                    text=message,
                    reply_markup=reply_markup,
                    parse_mode="Markdown"
                )
        else:
            # Suspicious activity below threshold -> kirim notifikasi manual
            message = (
                f"⚠️ **Suspicious INBOUND Activity**\n\n"
                f"🕒 {anomali_data['timestamp']}\n"
                f"🔍 Signature: `{sig}`\n"
                f"📍 Attacker IP: `{anomali_data['src_ip']}`\n"
                f"🎯 Target IP: `{anomali_data.get('dst_ip', LOCAL_IP)}`\n"
                f"📊 Confidence: {confidence:.2f}\n"
                f"ℹ️ Monitoring activity (below threshold)"
            )

            keyboard = [
                [InlineKeyboardButton("🛡️ Block IP", callback_data=f"blokir_{anomali_data['src_ip']}")],
                [InlineKeyboardButton("📊 Status", callback_data="status_bot")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)

            await bot.send_message(
                chat_id=config["chat_id"],
                text=message,
                reply_markup=reply_markup,
                parse_mode="Markdown"
            )

    except Exception as e:
        logger.error(f"Error in kirim_notifikasi: {e}")


# ========== SURICATA MONITORING (INBOUND ONLY) ==========
def extract_pcap_for_alert(event, outdir="/var/log/suricata/alerts_pcap", tshark_bin="tshark"):
    """
    Try several ways to get a pcap for this alert:
      1) If event contains 'capture_file' (Suricata pcap-log multi/conditional), copy it.
      2) Else, search configured Suricata pcap dir and run tshark filter to extract matching packets.
    Returns path to extracted/copy pcap, or None on failure.
    """
    try:
        Path(outdir).mkdir(parents=True, exist_ok=True)
        ts_str = event.get('timestamp')
        try:
            ts = dateparser.parse(ts_str) if ts_str else None
        except Exception:
            ts = None

        # 1) If Suricata already supplied capture_file in event (preferred)
        if 'capture_file' in event and event['capture_file']:
            src = Path(event['capture_file'])
            if src.exists():
                dst = Path(outdir) / f"alert_{event.get('src_ip','unknown')}_{int(time.time())}.pcap"
                try:
                    shutil.copy2(src, dst)
                    logger.info(f"Copied capture_file for alert -> {dst}")
                    return str(dst)
                except Exception as e:
                    logger.warning(f"Failed to copy capture_file {src}: {e}")

        # 2) Fallback: try to extract from Suricata pcap dir with tshark
        # Adjust pcap_dir to whatever your suricata writes to (default: /var/log/suricata/pcap)
        pcap_dir = "/var/log/suricata/pcap"
        if not os.path.isdir(pcap_dir):
            logger.debug(f"No pcap dir found at {pcap_dir}, skipping tshark extraction.")
            return None

        # Build tshark display filter
        src_ip = event.get('src_ip')
        dst_ip = event.get('dst_ip') or event.get('dest_ip')
        src_port = event.get('src_port') or event.get('sport') or 0
        dst_port = event.get('dest_port') or event.get('dest_port') or 0
        proto = (event.get('proto') or "").lower()

        filters = []
        if src_ip:
            filters.append(f"ip.src == {src_ip}")
        if dst_ip:
            filters.append(f"ip.dst == {dst_ip}")
        # port filter depends on proto
        if proto == 'tcp':
            if src_port:
                filters.append(f"tcp.srcport == {int(src_port)}")
            if dst_port:
                filters.append(f"tcp.dstport == {int(dst_port)}")
        elif proto == 'udp':
            if src_port:
                filters.append(f"udp.srcport == {int(src_port)}")
            if dst_port:
                filters.append(f"udp.dstport == {int(dst_port)}")
        # time window +/- 2s around timestamp if available (tshark supports frame.time_epoch)
        time_filter = ""
        tmp_out = None

        # Iterate pcap files in pcap_dir (newest first)
        pcap_files = sorted(Path(pcap_dir).glob("**/*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not pcap_files:
            logger.debug("No pcap files found in pcap dir for fallback extraction")
            return None

        for pcap_file in pcap_files:
            # compose display filter
            disp = " and ".join(filters) if filters else ""
            # if timestamp available, filter frames by epoch window (frame.time_epoch)
            if ts:
                epoch = ts.timestamp()
                start = epoch - 2
                end = epoch + 2
                # tshark display filter syntax for frame.time_epoch
                time_filter = f"(frame.time_epoch >= {start} and frame.time_epoch <= {end})"
                if disp:
                    disp = f"({disp}) and {time_filter}"
                else:
                    disp = time_filter

            out_pcap = Path(outdir) / f"alert_extract_{pcap_file.stem}_{int(time.time())}.pcap"
            cmd = [tshark_bin, "-r", str(pcap_file)]
            if disp:
                cmd += ["-Y", disp]
            cmd += ["-w", str(out_pcap)]

            try:
                # set reasonable timeout (configurable); using 15s here
                subprocess.run(cmd, check=True, timeout=15)
                if out_pcap.exists() and out_pcap.stat().st_size > 24:  # pcap header size check
                    logger.info(f"Extracted pcap for alert into {out_pcap}")
                    return str(out_pcap)
                else:
                    # remove empty output
                    try:
                        out_pcap.unlink(missing_ok=True)
                    except Exception:
                        pass
            except subprocess.TimeoutExpired:
                logger.warning(f"tshark timed out extracting from {pcap_file}, trying next file.")
            except Exception as e:
                logger.debug(f"tshark failed on {pcap_file}: {e}")
                # try next pcap file
                continue

        logger.debug("Failed to extract pcap for alert from pcap_dir")
        return None

    except Exception as e:
        logger.error(f"extract_pcap_for_alert error: {e}")
        return None

def pantau_eve(queue):
    global shutdown_flag, current_log_file
    
    while not shutdown_flag:
        try:
            log_file = get_latest_suricata_log()
            if not log_file:
                logger.warning("No Suricata log file found, waiting...")
                time.sleep(5)
                continue
                
            current_log_file = log_file
            current_inode = os.stat(current_log_file).st_ino
            logger.info(f"Monitoring INBOUND traffic: {current_log_file}")
            
            with open(current_log_file, 'r') as f:
                f.seek(0, 2)  # Move to end of file
                
                while not shutdown_flag:
                    try:
                        if not os.path.exists(current_log_file) or os.stat(current_log_file).st_ino != current_inode:
                            logger.info("Log file rotated, checking for new file...")
                            new_file = get_latest_suricata_log()
                            if new_file and new_file != current_log_file:
                                current_log_file = new_file
                                current_inode = os.stat(current_log_file).st_ino
                                f = open(current_log_file, 'r')
                                f.seek(0, 2)
                                logger.info(f"Switched to new log file: {current_log_file}")
                                continue
                            else:
                                time.sleep(1)
                                continue
                            
                        line = f.readline()
                        if not line:
                            time.sleep(0.1)
                            continue
                            
                        try:
                            data = json.loads(line)
                            if data.get("event_type") == "alert":
                                # Process only inbound traffic (to local IP)
                                if data.get("dest_ip") == LOCAL_IP and data.get("src_ip") != LOCAL_IP:
                                    logger.debug(f"Raw INBOUND alert: {data}")
                                    
                                    if not data.get("alert", {}).get("signature"):
                                        continue
                                        
                                    anomali_data = {
                                        "timestamp": data.get("timestamp", datetime.now().isoformat()),
                                        "src_ip": data.get("src_ip"),
                                        "dst_ip": data.get("dest_ip", ""),
                                        "src_port": data.get("src_port", 0),
                                        "dest_port": data.get("dest_port", 0),
                                        "proto": data.get("proto", "unknown"),
                                        "signature": data["alert"].get("signature", "Unknown"),
                                        "flow": data.get("flow", {}),
                                        "alert": data.get("alert", {}),
                                        "direction": "inbound"
                                    }
                                    
                                    logger.info(f"New INBOUND alert: {anomali_data['src_ip']} -> {anomali_data['dst_ip']} - {anomali_data['signature']}")
                                    # Try to get pcap for this alert (blocking, but timeouted)
                                    try:
                                        pcap_path = extract_pcap_for_alert(data)
                                        if pcap_path:
                                            anomali_data['pcap_file'] = pcap_path
                                    except Exception as e:
                                        logger.debug(f"Failed to attach pcap for alert: {e}")
                                    
                                    queue.put(anomali_data)
                                    simpan_log(
                                        anomali_data['timestamp'],
                                        anomali_data['src_ip'],
                                        anomali_data['dst_ip'],
                                        anomali_data['signature'],
                                        "detected",
                                        direction="inbound"
                                    )
                        except json.JSONDecodeError:
                            logger.warning("Invalid JSON in log line")
                        except Exception as e:
                            logger.error(f"Error processing log entry: {e}")
                            
                    except Exception as e:
                        logger.error(f"Error during log monitoring: {e}")
                        break
                        
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
            time.sleep(5)

# ========== MAIN APPLICATION ==========
async def run_application():
    global application, bot, shutdown_flag, drl_analyzer, processed_events, current_log_file, LOCAL_IP, config
    
    shutdown_flag = False
    processed_events = {}
    config = load_config()
    LOCAL_IP = get_local_ip()
    init_db()
    init_dataset()  # Inisialisasi dataset
    
    try:
        drl_analyzer = DRLAnalyzer(config["drl_model_path"])
    except Exception as e:
        logger.critical(f"Failed to initialize DRL analyzer: {e}")
        return

    monitoring_queue = Queue()
    
    try:
        application = Application.builder().token(config["token"]).build()
        bot = application.bot
        
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("status", cek_status))
        application.add_handler(CallbackQueryHandler(handle_callback))
        application.add_error_handler(error_handler)
        
    except Exception as e:
        logger.critical(f"Failed to initialize Telegram bot: {e}")
        return
    
    monitoring_thread = Thread(
        target=pantau_eve,
        args=(monitoring_queue,),
        daemon=True
    )
    monitoring_thread.start()
    
    async def process_queue():
        while not shutdown_flag:
            try:
                anomali_data = await asyncio.to_thread(monitoring_queue.get)
                await kirim_notifikasi(anomali_data)
            except Exception as e:
                logger.error(f"Queue processing error: {e}")
    
    asyncio.create_task(process_queue())
    
    logger.info("[*] Starting INBOUND anomaly detection system...")
    try:
        await application.initialize()
        await application.start()
        await application.updater.start_polling()
        await send_welcome_message()
        
        while not shutdown_flag:
            await asyncio.sleep(1)
    except Exception as e:
        logger.critical(f"Error running application: {e}")
    finally:
        logger.info("Shutting down...")
        try:
            await application.updater.stop()
            await application.stop()
            await application.shutdown()
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        logger.info("[*] System shutdown complete")

def shutdown_handler(signum, frame):
    global shutdown_flag
    logger.info("\n🛑 Received shutdown signal...")
    shutdown_flag = True

if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    
    try:
        asyncio.run(run_application())
    except Exception as e:
        logger.critical(f"[!] Fatal error: {e}")
    finally:
        logger.info("[*] System shutdown complete")
