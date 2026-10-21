import telebot
from flask import Flask, request, jsonify
import threading
import json
import os

# Configuration
def load_bot_token():
    """Read the token from TELEGRAM_BOT_TOKEN or the .bot_token file next to this script."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if token:
        return token
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".bot_token")
    try:
        with open(path) as f:
            token = f.read().strip()
    except OSError:
        token = ""
    if not token:
        raise SystemExit("Telegram bot token not found: set TELEGRAM_BOT_TOKEN or create " + path)
    return token


BOT_TOKEN = load_bot_token()
DATA_FILE = "admin_data.json"
PORT = 5005

bot = telebot.TeleBot(BOT_TOKEN)
app = Flask(__name__)

# Store for admin chat ID
admin_chat_id = None

def load_admin_data():
    global admin_chat_id
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                data = json.load(f)
                admin_chat_id = data.get("chat_id")
                print(f"Loaded Admin Chat ID: {admin_chat_id}")
        except Exception as e:
            print(f"Error loading admin data: {e}")

def save_admin_data(chat_id):
    global admin_chat_id
    admin_chat_id = chat_id
    try:
        with open(DATA_FILE, 'w') as f:
            json.dump({"chat_id": chat_id}, f)
        print(f"Saved Admin Chat ID: {chat_id}")
    except Exception as e:
        print(f"Error saving admin data: {e}")

# --- Telegram Bot Handlers ---
@bot.message_handler(commands=['start'])
def send_welcome(message):
    global admin_chat_id
    chat_id = message.chat.id
    
    if admin_chat_id is None:
        save_admin_data(chat_id)
        bot.reply_to(message, "Assalomu alaykum! Siz administrator sifatida ro'yxatga olindingiz. Endi tarmoqdagi xatoliklar haqida xabarlar qabul qilasiz.")
    elif admin_chat_id == chat_id:
        bot.reply_to(message, "Siz allaqachon administrator sifatida ro'yxatdan o'tgansiz.")
    else:
        bot.reply_to(message, "Kechirasiz, ushbu bot faqat bitta administrator (birinchi yozgan foydalanuvchi) bilan ishlaydi.")

@bot.message_handler(commands=['status'])
def send_status(message):
    global admin_chat_id
    if message.chat.id == admin_chat_id:
         bot.reply_to(message, "Tizim ishlamoqda. Xabarlar qabul qilishga tayyor.")

# --- Flask Server ---
@app.route('/notify', methods=['POST'])
def notify():
    global admin_chat_id
    if not admin_chat_id:
        return jsonify({"status": "error", "message": "No admin registered yet. Please start the bot first."}), 400

    data = request.json
    if not data or "message" not in data:
        return jsonify({"status": "error", "message": "Missing 'message' field in JSON body"}), 400

    msg_text = data["message"]
    buttons_data = data.get("buttons")
    
    markup = None
    if buttons_data:
        markup = telebot.types.InlineKeyboardMarkup()
        for row in buttons_data:
            # row is a list of dicts: [{"text": "Ignore", "callback_data": "ignore|id"}]
            btn_row = [telebot.types.InlineKeyboardButton(text=btn["text"], callback_data=btn["callback_data"]) for btn in row]
            markup.add(*btn_row)

    try:
        # Send message to admin
        bot.send_message(admin_chat_id, msg_text, parse_mode="HTML", reply_markup=markup)
        return jsonify({"status": "success", "message": "Notification sent"}), 200
    except Exception as e:
        print(f"Error sending telegram message: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# --- Callback Query Handler ---
import requests as sync_requests
GO_BACKEND_URL = "http://127.0.0.1:8088/api/bot/action"

@bot.callback_query_handler(func=lambda call: True)
def handle_query(call):
    data = call.data
    # data format: action|issue_id, e.g., "ignore|shadow_192.168.1.1_12"
    parts = data.split("|", 1)
    if len(parts) != 2:
        bot.answer_callback_query(call.id, "Noma'lum buyruq!")
        return

    action, issue_id = parts[0], parts[1]
    
    # Send action to Go backend
    try:
        payload = {"action": action, "issue_id": issue_id}
        resp = sync_requests.post(GO_BACKEND_URL, json=payload, timeout=5)
        
        if resp.status_code == 200:
            if action == "ignore":
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, 
                                      text=f"{call.message.html_text}\n\n✅ <b>E'tiborsiz qoldirildi (Ignored).</b> Keyingi hisobotlarda chiqmaydi.", 
                                      parse_mode="HTML")
                bot.answer_callback_query(call.id, "Muammo e'tiborsiz qoldirildi.")
            elif action == "verify":
                bot.edit_message_text(chat_id=call.message.chat.id, message_id=call.message.message_id, 
                                      text=f"{call.message.html_text}\n\n🔄 <b>To'g'rilandi deb belgilanib, qayta tekshirilmoqda...</b>", 
                                      parse_mode="HTML")
                bot.answer_callback_query(call.id, "Qayta tekshirish (Rescan) boshlandi.")
        else:
             bot.answer_callback_query(call.id, "Xatolik yuz berdi. Go server ishlayotganiga ishonch hosil qiling.")
    except Exception as e:
        print(f"Error calling Go backend: {e}")
        bot.answer_callback_query(call.id, "Tarmoq xatosi: Go serverga ulanib bo'lmadi.")

def run_flask():
    print(f"Starting Flask server on port {PORT}...")
    # use threaded=True to handle requests concurrently
    app.run(host='127.0.0.1', port=PORT, debug=False, use_reloader=False, threaded=True)

if __name__ == '__main__':
    load_admin_data()
    
    # Start Flask API in a separate thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    print("Starting Telegram Bot long-polling...")
    # Start bot polling
    bot.infinity_polling()
