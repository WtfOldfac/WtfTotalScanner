import hashlib
import json
import os
import sqlite3
import tempfile
import logging
from datetime import datetime
from typing import Dict, Any

# ====== НАСТРОЙКА ЛОГИРОВАНИЯ ======
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)  # ✅ ИСПРАВЛЕНО

# ====== КОНФИГУРАЦИЯ ======
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN')
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

if not TELEGRAM_TOKEN or not VT_API_KEY:
    logger.error("Не установлены переменные окружения!")

# ====== БАЗА ДАННЫХ ======
DB_PATH = '/tmp/vt_cache.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_cache (
            file_hash TEXT PRIMARY KEY,
            vt_report TEXT,
            positives INTEGER,
            total INTEGER,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# ====== КЭШ ======
def get_file_hash(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()

def check_cache(file_hash: str) -> Dict[str, Any]:
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT vt_report, positives, total FROM file_cache WHERE file_hash = ?",
            (file_hash,)
        )
        result = cursor.fetchone()
        conn.close()
        if result:
            return {
                'cached': True,
                'positives': result[1],
                'total': result[2],
                'report': json.loads(result[0])
            }
    except Exception as e:
        logger.error(f"Ошибка кэша: {e}")
    return {'cached': False}

def save_to_cache(file_hash: str, report_data: Dict[str, Any], positives: int, total: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO file_cache (file_hash, vt_report, positives, total) VALUES (?, ?, ?, ?)",
            (file_hash, json.dumps(report_data), positives, total)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Ошибка сохранения: {e}")

# ====== VIRUSTOTAL ======
def scan_with_virustotal(file_bytes: bytes, filename: str) -> Dict[str, Any]:  # ✅ ИСПРАВЛЕНО
    """Отправляет файл в VirusTotal через API v3"""
    try:
        import requests
        
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": VT_API_KEY}
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name
        
        try:
            with open(tmp_path, 'rb') as f:
                files = {"file": (filename, f)}
                response = requests.post(url, headers=headers, files=files)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id')
                return get_analysis_result(analysis_id)
            else:
                return {"error": f"API Error: {response.status_code}"}
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    except Exception as e:
        logger.error(f"Ошибка сканирования: {str(e)}")
        return {"error": f"Scan error: {str(e)}"}

def get_analysis_result(analysis_id: str) -> Dict[str, Any]:
    import requests
    import time
    
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    
    for _ in range(30):
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            status = data.get('data', {}).get('attributes', {}).get('status')
            if status == 'completed':
                return format_vt_response(data)
            elif status == 'queued':
                time.sleep(1)
                continue
        time.sleep(1)
    
    return {"error": "Timeout"}
def format_vt_response(vt_data: Dict[str, Any]) -> Dict[str, Any]:
    attributes = vt_data.get('data', {}).get('attributes', {})
    stats = attributes.get('stats', {})
    return {
        'positives': stats.get('malicious', 0),
        'total': sum(stats.values()),
        'permalink': f"https://www.virustotal.com/gui/file/{attributes.get('sha256')}",
        'results': attributes.get('results', {})
    }

# ====== TELEGRAM ======
async def handle_telegram_update(event_data: Dict[str, Any]):
    try:
        from telegram import Update
        from telegram.ext import Application
        
        application = Application.builder().token(TELEGRAM_TOKEN).build()
        update = Update.de_json(event_data, application.bot)
        
        if update.message and update.message.document:
            return await process_document(update)
        elif update.message and update.message.text:
            return await process_text(update)
    except Exception as e:
        logger.error(f"Ошибка Telegram: {e}")
        return {"error": str(e)}
    return {"status": "no_action"}

async def process_document(update):
    from telegram import Bot
    
    bot = Bot(token=TELEGRAM_TOKEN)
    document = update.message.document
    
    try:
        file = await bot.get_file(document.file_id)
        file_bytes = await file.download_as_bytearray()
        filename = document.file_name or "unknown"
        
        if len(file_bytes) > 32 * 1024 * 1024:
            await update.message.reply_text("❌ Файл слишком большой (макс 32 МБ)")
            return {"status": "size_limit"}
        
        file_hash = get_file_hash(file_bytes)
        cache_result = check_cache(file_hash)
        
        if cache_result['cached']:
            await update.message.reply_text(
                f"✅ Файл уже проверялся\n"
                f"📊 Результат: {cache_result['positives']}/{cache_result['total']}\n"
                f"🔗 https://www.virustotal.com/gui/file/{file_hash}"
            )
            return {"status": "cached"}
        
        await update.message.reply_text("🔄 Проверяю в VirusTotal...")
        scan_result = scan_with_virustotal(file_bytes, filename)
        
        if "error" in scan_result:
            await update.message.reply_text(f"❌ Ошибка: {scan_result['error']}")
            return {"status": "error"}
        
        positives = scan_result.get('positives', 0)
        total = scan_result.get('total', 0)
        save_to_cache(file_hash, scan_result, positives, total)
        
        result_message = f"📊 *Результат проверки {filename}*\n\n"
        result_message += f"✅ Проверено: {total} антивирусов\n"
        result_message += f"⚠️ Обнаружено угроз: {positives}\n\n"
        
        if positives > 0:
            result_message += "🔴 *Обнаружены угрозы!*\n"
            results = scan_result.get('results', {})
            count = 0
            for av_name, result in results.items():
                if result.get('category') == 'malicious':
                    count += 1
                    result_message += f"• *{av_name}*: {result.get('result', 'Unknown')}\n"
                    if count >= 3:
                        break
        else:
            result_message += "🟢 *Угроз не обнаружено*\n"
        
        result_message += f"\n🔗 [Подробный отчет]({scan_result.get('permalink')})"
        
        await update.message.reply_text(
            result_message,
            parse_mode='Markdown',
            disable_web_page_preview=True
        )
        
        return {"status": "success", "positives": positives, "total": total}
    
    except Exception as e:
        logger.error(f"Ошибка документа: {e}")
        await update.message.reply_text("❌ Ошибка обработки файла")
        return {"status": "error"}

async def process_text(update):
text = update.message.text
    
    if text.startswith('/start'):
        await update.message.reply_text(
            "🛡️ *WTF Total Scanner*\n\n"
            "Отправьте файл для проверки через VirusTotal\n"
            "Максимальный размер: 32 МБ",
            parse_mode='Markdown'
        )
    elif text.startswith('/help'):
        await update.message.reply_text("Просто отправьте файл для проверки")
    
    return {"status": "text_processed"}

# ====== ОСНОВНОЙ ОБРАБОТЧИК ======
def handler(event, context):
    try:
        logger.info(f"Получен запрос: {event.get('httpMethod')}")
        
        if event['httpMethod'] != 'POST':
            return {
                'statusCode': 405,
                'body': json.dumps({'error': 'Method Not Allowed'}),
                'headers': {'Content-Type': 'application/json'}
            }
        
        body = json.loads(event['body'])
        import asyncio
        result = asyncio.run(handle_telegram_update(body))
        
        return {
            'statusCode': 200,
            'body': json.dumps({'status': 'ok', 'result': result}),
            'headers': {'Content-Type': 'application/json'}
        }
    
    except Exception as e:
        logger.error(f"Критическая ошибка: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)}),
            'headers': {'Content-Type': 'application/json'}
        }

# ====== ЛОКАЛЬНОЕ ТЕСТИРОВАНИЕ ======
if __name__ == '__main__':  # ✅ ИСПРАВЛЕНО
    print("WTF Total Scanner Bot")
    print("=" * 50)
    print(f"TELEGRAM_TOKEN: {'✅' if TELEGRAM_TOKEN else '❌'}")
    print(f"VIRUSTOTAL_API_KEY: {'✅' if VT_API_KEY else '❌'}")
    print(f"Database: {DB_PATH}")
    print("Бот готов к работе на Netlify!")