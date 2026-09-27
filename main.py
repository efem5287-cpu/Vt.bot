import os
import requests
import telebot

# Bilgilerin
BOT_TOKEN = "8944877188:AAEYZxcVx4vFi6GdpNuGQyw9H65QoqSRrHA"
VT_API_KEY = "Dd879532277e4c9e19490a5c4e348ab1f714d03792b4046e7b017aa9d36d38aa"

# Zorunlu kanallar
CHANNELS = ["swarovskiyeniden", "swarovskihile"]

bot = telebot.TeleBot(BOT_TOKEN)
VT_URL = "https://www.virustotal.com/api/v3/urls"

# Veri tabanı simülasyonu (Bellekte tutulur)
user_refs = {}  # {user_id: davet_sayisi}
referred_users = set()  # Zaten birinin referansıyla gelenler
admin_sessions = set()  # Admin şifresini girip yetki alanlar


# Kanal kontrol fonksiyonu
def check_all_channels(user_id):
  for channel in CHANNELS:
    try:
      member = bot.get_chat_member(f"@{channel}", user_id)
      if member.status not in ["member", "administrator", "creator"]:
        return False
    except Exception:
      return False
  return True


@bot.message_handler(commands=["start"])
def send_welcome(message):
  user_id = message.from_user.id
  args = message.text.split()

  # 1. Referans Sistemi (Gerçekten start verenler sayılır)
  if len(args) > 1:
    ref_id = args[1]
    if ref_id.isdigit():
      ref_id = int(ref_id)
      # Kişi kendisini davet edemez ve daha önce başka bir ref ile gelmemiş olmalı
      if ref_id != user_id and user_id not in referred_users:
        referred_users.add(user_id)
        user_refs[ref_id] = user_refs.get(ref_id, 0) + 1
        try:
          bot.send_message(
              ref_id,
              "🎉 Tebrikler! Davet ettiğin kişi bota giriş yaptı ve referansın"
              " sayıldı!",
          )
        except Exception:
          pass

  # Eğer kullanıcı admin giriş yapmışsa direkt ana menüye al
  if user_id in admin_sessions:
    bot.reply_to(
        message,
        "👑 **Admin Modu Aktif!** Sınırsız bir şekilde link gönderebilirsin.",
    )
    return

  # 2. Kanal Zorunluluğu Kontrolü
  if not check_all_channels(user_id):
    markup = telebot.types.InlineKeyboardMarkup()
    markup.add(
        telebot.types.InlineKeyboardButton(
            "📢 1. Kanalımıza Katıl", url="https://t.me/swarovskiyeniden"
        )
    )
    markup.add(
        telebot.types.InlineKeyboardButton(
            "📢 2. Kanalımıza Katıl", url="https://t.me/swarovskihile"
        )
    )
    markup.add(
        telebot.types.InlineKeyboardButton(
            "✅ Katıldım, Kontrol Et", callback_data="check_sub"
        )
    )

    bot.reply_to(
        message,
        "⚠️ Botu kullanabilmek için **her iki kanalımıza da** katılmalısın!",
        reply_markup=markup,
    )
    return

  # Normal Kullanıcı Menüsü ve Ref Linki
  my_refs = user_refs.get(user_id, 0)
  bot_info = bot.get_me()
  ref_link = f"https://t.me/{bot_info.username}?start={user_id}"

  welcome_text = (
      f"Selam! Ben VirusTotal Tarama Botuyum.\n"
      f"Bana bir **URL** gönder, taratıp sonucunu söyleyeyim.\n\n"
      f"👥 **Referans Sistemi:**\n"
      f"Davet ettiğin ve bota start veren kişi sayısı: {my_refs}\n"
      f"🔗 Davet Linkin:\n`{ref_link}`"
  )
  bot.reply_to(message, welcome_text, parse_mode="Markdown")


# Admin Paneli Giriş Komutu: /admin efe01
@bot.message_handler(commands=["admin"])
def admin_login(message):
  user_id = message.from_user.id
  args = message.text.split()

  if len(args) > 1 and args[1] == "efe01":
    admin_sessions.add(user_id)
    bot.reply_to(
        message,
        "✅ **Admin girişi başarılı!** Artık kanallara veya reklamlara takılmadan"
        " botu sınırsız kullanabilirsin.",
    )
  else:
    bot.reply_to(
        message,
        "❌ Hatalı şifre! Kullanım: `/admin şifre` şeklinde yazmalısın.",
    )


# Üyelik kontrol butonu
@bot.callback_query_handler(func=lambda call: call.data == "check_sub")
def callback_query(call):
  user_id = call.from_user.id
  if check_all_channels(user_id):
    bot.answer_callback_query(call.id, "Tebrikler, tüm kanallara katıldın!")
    bot.send_message(
        call.message.chat.id,
        "Harika! Artık botu kullanabilirsin. Link gönderebilirsin.",
    )
  else:
    bot.answer_callback_query(
        call.id,
        "Eksik kanal var! Lütfen iki kanala da katıldığından emin ol.",
        show_alert=True,
    )


# URL Tarama ve Mesaj Yönetimi
@bot.message_handler(func=lambda message: True)
def check_url(message):
  user_id = message.from_user.id

  # Admin ise kanal kontrolünü es geç
  if user_id not in admin_sessions:
    if not check_all_channels(user_id):
      bot.reply_to(
          message,
          "⚠️ Botu kullanabilmek için önce şu iki kanala da katılmalısın:\n👉"
          " @swarovskiyeniden\n👉 @swarovskihile\n\nSonrasında /start komutunu"
          " gönder.",
      )
      return

  url_to_scan = message.text

  if not url_to_scan.startswith("http"):
    bot.reply_to(
        message, "Lütfen geçerli bir link gönder (http:// veya https:// ile)."
    )
    return

  bot.reply_to(message, "Link VirusTotal'a gönderildi, inceleniyor...")

  headers = {"x-apikey": VT_API_KEY}
  data = {"url": url_to_scan}

  try:
    response = requests.post(VT_URL, headers=headers, data=data)
    if response.status_code == 200:
      result_id = response.json()["data"]["id"]
      analysis_url = f"https://www.virustotal.com/api/v3/analyses/{result_id}"
      analysis_res = requests.get(analysis_url, headers=headers)

      if analysis_res.status_code == 200:
        stats = analysis_res.json()["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        reply_text = (
            f"🔍 **VirusTotal Tarama Sonucu:**\n\n"
            f"🔴 Zararlı (Malicious): {malicious}\n"
            f"🟡 Şüpheli (Suspicious): {suspicious}\n"
            f"🟢 Temiz (Harmless): {harmless}"
        )
        bot.reply_to(message, reply_text)
      else:
        bot.reply_to(message, "Sonuçlar alınamadı, daha sonra tekrar dene.")
    else:
      bot.reply_to(
          message, "VirusTotal API bağlantısında bir hata oluştu."
      )
  except Exception as e:
    bot.reply_to(message, f"Bir hata oluştu: {str(e)}")


if __name__ == "__main__":
  print("Bot admin paneli ve gerçek ref sistemiyle çalışıyor...")
  bot.infinity_polling()
  
