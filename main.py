import os
import requests
import telebot

# Kendi anahtarlarını buraya yaz
BOT_TOKEN = "8944877188:AAEYZxcVx4vFi6GdpNuGQyw9H65QoqSRrHA"
VT_API_KEY = "dd879532277e4c9e19490a5c4e348ab1f714d03792b4046e7b017aa9d36d38aa"

bot = telebot.TeleBot(BOT_TOKEN)
VT_URL = "https://www.virustotal.com/api/v3/urls"


@bot.message_handler(commands=["start", "help"])
def send_welcome(message):
  bot.reply_to(
      message,
      "Selam! Bana taratmak istediğin bir **URL (web sitesi linki)** gönder,"
      " onu VirusTotal'da taratıp sonucunu sana söyleyeyim.",
  )


@bot.message_handler(func=lambda message: True)
def check_url(message):
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
    # 1. URL'yi taratmaya gönder
    response = requests.post(VT_URL, headers=headers, data=data)
    if response.status_code == 200:
      result_id = response.json()["data"]["id"]

      # 2. Sonucu al
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
  print("Bot çalışıyor...")
  bot.infinity_polling()
