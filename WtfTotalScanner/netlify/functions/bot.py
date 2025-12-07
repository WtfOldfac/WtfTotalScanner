import hashlib
import json
import os
import sqlite3
import tempfile
import logging
from datetime import datetime
from typing import Dict, Any

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(name)

# ====== КОНФИГУРАЦИЯ ======
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN')
VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

# Проверка переменных окружения
if not TELEGRAM_TOKEN:
    logger.error("TELEGRAM_TOKEN не установлен!")
if not VT_API_KEY:
    logger.error("VIRUSTOTAL_API_KEY не установлен!")

# ====== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ ======
DB_PATH = '/tmp/vt_cache.db'

def init_db():
    """Инициализирует базу данных SQLite"""
    try:
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
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS recent_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT,
                file_name TEXT,
                user_id INTEGER,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("База данных инициализирована")
    except Exception as e:
        logger.error(f"Ошибка инициализации БД: {e}")

# Инициализируем БД при импорте
init_db()

# ====== РАБОТА С КЭШЕМ ======
def get_file_hash(file_bytes: bytes) -> str:
    """Генерирует SHA-256 хэш файла"""
    return hashlib.sha256(file_bytes).hexdigest()

def check_cache(file_hash: str) -> Dict[str, Any]:
    """Проверяет кэш в SQLite"""
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
            report_data = json.loads(result[0])
            return {
                'cached': True,
                'report': report_data,
                'positives': result[1],
                'total': result[2],
                'scan_date': report_data.get('scan_date', 'Неизвестно')
            }
    except Exception as e:
        logger.error(f"Ошибка проверки кэша: {e}")
    
    return {'cached': False}

def save_to_cache(file_hash: str, report_data: Dict[str, Any], positives: int, total: int):
    """Сохраняет отчёт в SQLite"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """INSERT OR REPLACE INTO file_cache 
               (file_hash, vt_report, positives, total) 
               VALUES (?, ?, ?, ?)""",
            (file_hash, json.dumps(report_data), positives, total)
        )
        conn.commit()
        conn.close()
        logger.info(f"Сохранено в кэш: {file_hash[:16]}...")
    except Exception as e:
        logger.error(f"Ошибка сохранения в кэш: {e}")

def log_scan(file_hash: str, file_name: str, user_id: int):
    """Логирует сканирование в БД"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """INSERT INTO recent_scans (file_hash, file_name, user_id)
               VALUES (?, ?, ?)""",
            (file_hash, file_name, user_id)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Ошибка логирования: {e}")

# ====== РАБОТА С VIRUSTOTAL ======
def scan_with_virustotal(file_bytes: bytes, filename: str) -> Dict[str, Any]:

"""Отправляет файл в VirusTotal через API v3"""
    try:
        import requests
        
        # Вариант 1: Используем прямой запрос к API v3
        url = "https://www.virustotal.com/api/v3/files"
        
        headers = {
            "x-apikey": VT_API_KEY,
        }
        
        # Создаем временный файл для загрузки
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp:
            tmp.write(file_bytes)
            tmp_path = tmp.name
        
        try:
            # Загружаем файл
            with open(tmp_path, 'rb') as f:
                files = {"file": (filename, f)}
                response = requests.post(url, headers=headers, files=files)
            
            if response.status_code == 200:
                data = response.json()
                analysis_id = data.get('data', {}).get('id')
                
                # Ждем результат анализа
                return get_analysis_result(analysis_id)
            else:
                error_msg = response.json().get('error', {}).get('message', 'Unknown error')
                logger.error(f"VirusTotal API Error: {error_msg}")
                return {"error": f"API Error: {error_msg}", "status_code": response.status_code}
        
        finally:
            # Удаляем временный файл
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    except ImportError:
        logger.error("Библиотека requests не установлена")
        return {"error": "Missing dependencies: requests"}
    except Exception as e:
        logger.error(f"Ошибка при сканировании: {str(e)}")
        return {"error": f"Scan error: {str(e)}"}

def get_analysis_result(analysis_id: str) -> Dict[str, Any]:
    """Получает результат анализа от VirusTotal"""
    import requests
    import time
    
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    
    # Ждем готовности результата (максимум 30 секунд)
    for _ in range(30):
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            status = data.get('data', {}).get('attributes', {}).get('status')
            
            if status == 'completed':
                return format_vt_response(data)
            elif status == 'queued':
                time.sleep(1)  # Ждем 1 секунду перед повторной проверкой
                continue
        
        time.sleep(1)
    
    return {"error": "Timeout waiting for analysis"}

def format_vt_response(vt_data: Dict[str, Any]) -> Dict[str, Any]:
    """Форматирует ответ от VirusTotal"""
    attributes = vt_data.get('data', {}).get('attributes', {})
    stats = attributes.get('stats', {})
    
    return {
        'scan_date': datetime.now().isoformat(),
        'file_info': {
            'sha256': attributes.get('sha256'),
            'md5': attributes.get('md5'),
            'sha1': attributes.get('sha1'),
            'size': attributes.get('size'),
            'type_description': attributes.get('type_description'),
        },
        'stats': stats,
        'results': attributes.get('results', {}),
        'positives': stats.get('malicious', 0),
        'total': sum(stats.values()),
        'permalink': f"https://www.virustotal.com/gui/file/{attributes.get('sha256')}"
    }

# ====== TELEGRAM БОТ ======
async def handle_telegram_update(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """Обрабатывает обновление от Telegram"""
    try:
        from telegram import Update
        from telegram.ext import Application, MessageHandler, filters, ContextTypes
        
        # Создаем приложение Telegram
        application = Application.builder().token(TELEGRAM_TOKEN).build()
        
        # Получаем обновление

update = Update.de_json(event_data, application.bot)
        
        if update.message and update.message.document:
            return await process_document(update)
        elif update.message and update.message.text:
            return await process_text(update)
    
    except Exception as e:
        logger.error(f"Ошибка обработки Telegram: {e}")
        return {"error": str(e)}
    
    return {"status": "no_action"}

async def process_document(update) -> Dict[str, Any]:
    """Обрабатывает документ от пользователя"""
    from telegram import Bot
    
    bot = Bot(token=TELEGRAM_TOKEN)
    user = update.effective_user
    document = update.message.document
    
    try:
        # Скачиваем файл
        file = await bot.get_file(document.file_id)
        file_bytes = await file.download_as_bytearray()
        filename = document.file_name or "unknown"
        
        # Проверяем размер
        if len(file_bytes) > 32 * 1024 * 1024:
            await update.message.reply_text(
                "❌ Файл слишком большой. Максимальный размер: 32 МБ"
            )
            return {"status": "size_limit"}
        
        # Получаем хэш
        file_hash = get_file_hash(file_bytes)
        
        # Проверяем кэш
        cache_result = check_cache(file_hash)
        
        if cache_result['cached']:
            # Используем кэшированный результат
            await update.message.reply_text(
                f"✅ Файл уже проверялся ранее\n"
                f"📊 Результат: {cache_result['positives']}/{cache_result['total']} антивирусов обнаружили угрозы\n"
                f"📅 Дата проверки: {cache_result['scan_date']}\n"
                f"🔗 Подробнее: https://www.virustotal.com/gui/file/{file_hash}"
            )
            return {"status": "cached", "hash": file_hash}
        
        # Отправляем сообщение о начале проверки
        await update.message.reply_text(
            f"🔄 Отправляю файл '{filename}' на проверку в VirusTotal...\n"
            f"⏳ Это займет около 30 секунд"
        )
        
        # Сканируем через VirusTotal
        scan_result = scan_with_virustotal(file_bytes, filename)
        
        if "error" in scan_result:
            await update.message.reply_text(
                f"❌ Ошибка при проверке: {scan_result['error']}"
            )
            return {"status": "error", "error": scan_result['error']}
        
        # Сохраняем результат
        positives = scan_result.get('positives', 0)
        total = scan_result.get('total', 0)
        
        save_to_cache(file_hash, scan_result, positives, total)
        log_scan(file_hash, filename, user.id)
        
        # Формируем ответ
        result_message = f"📊 *Результат проверки {filename}*\n\n"
        result_message += f"✅ Проверено: {total} антивирусов\n"
        result_message += f"⚠️  Обнаружено угроз: {positives}\n\n"
        
        if positives > 0:
            result_message += "🔴 *Обнаружены угрозы!*\n"
            # Добавляем информацию о конкретных антивирусах
            results = scan_result.get('results', {})
            malicious_count = 0
            for av_name, result in results.items():
                if result.get('category') == 'malicious':
                    malicious_count += 1
                    result_message += f"• *{av_name}*: {result.get('result', 'Unknown')}\n"
                    if malicious_count >= 5:  # Показываем только первые 5
                        remaining = positives - 5
                        if remaining > 0:
                            result_message += f"• ...и еще {remaining} антивирусов\n"
                        break
        else:
            result_message += "🟢 *Угроз не обнаружено*\n"
        
        result_message += f"\n🔗 [Подробный отчет на VirusTotal]({scan_result.get('permalink')})"

await update.message.reply_text(
            result_message,
            parse_mode='Markdown',
            disable_web_page_preview=True
        )
        
        return {
            "status": "scanned",
            "hash": file_hash,
            "positives": positives,
            "total": total
        }
    
    except Exception as e:
        logger.error(f"Ошибка обработки документа: {e}")
        await update.message.reply_text("❌ Произошла ошибка при обработке файла")
        return {"status": "error", "error": str(e)}

async def process_text(update) -> Dict[str, Any]:
    """Обрабатывает текстовые сообщения"""
    text = update.message.text
    
    if text.startswith('/start'):
        await update.message.reply_text(
            "🛡️ *WTF Total Scanner*\n\n"
            "Отправьте мне любой файл (до 32 МБ), и я проверю его через VirusTotal.\n\n"
            "⚠️ *Важно:* Файлы временно загружаются на сервер VirusTotal.\n"
            "Результаты кэшируются для ускорения повторных проверок.",
            parse_mode='Markdown'
        )
    elif text.startswith('/help'):
        await update.message.reply_text(
            "📋 *Помощь*\n\n"
            "Просто отправьте мне файл для проверки.\n"
            "Поддерживаются все типы файлов до 32 МБ.\n\n"
            "Команды:\n"
            "/start - Начало работы\n"
            "/help - Эта справка\n"
            "/stats - Статистика проверок",
            parse_mode='Markdown'
        )
    elif text.startswith('/stats'):
        # Показываем статистику из БД
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM file_cache")
            total_scans = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM recent_scans")
            user_scans = cursor.fetchone()[0]
            conn.close()
            
            await update.message.reply_text(
                f"📈 *Статистика*\n\n"
                f"• Всего проверено файлов: {total_scans}\n"
                f"• Всего сканирований: {user_scans}\n"
                f"• Кэш базы: {DB_PATH}",
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Ошибка получения статистики: {e}")
            await update.message.reply_text("❌ Ошибка получения статистики")
    
    return {"status": "text_processed"}

# ====== ОСНОВНОЙ ОБРАБОТЧИК NETLIFY ======
def handler(event, context):
    """Основной обработчик для Netlify Functions"""
    try:
        # Логируем входящий запрос
        logger.info(f"Получен запрос: {event.get('httpMethod')}")
        
        if event['httpMethod'] != 'POST':
            return {
                'statusCode': 405,
                'body': json.dumps({'error': 'Method Not Allowed'}),
                'headers': {'Content-Type': 'application/json'}
            }
        
        # Парсим тело запроса
        try:
            body = json.loads(event['body'])
        except json.JSONDecodeError:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Invalid JSON'}),
                'headers': {'Content-Type': 'application/json'}
            }
        
        # Для локального тестирования
        import asyncio
        
        # Обрабатываем обновление
        result = asyncio.run(handle_telegram_update(body))
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'status': 'ok',
                'result': result
            }),
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
if __name__ == '__main__':
    print("WTF Total Scanner Bot")
    print("=" * 50)
    print(f"TELEGRAM_TOKEN: {'✅' if TELEGRAM_TOKEN else '❌'}")
    print(f"VIRUSTOTAL_API_KEY: {'✅' if VT_API_KEY else '❌'}")
    print(f"Database: {DB_PATH}")
    print("Бот готов к работе на Netlify!")