Telegram Phishing Domain Detector


This project is an advanced Python bot that continuously monitors a specified list of domains to detect websites showing signs of phishing. When a suspicious domain is found, the bot instantly sends an alert with full analysis details to a designated Telegram group.

🌟 Key Features
Advanced Analysis: It doesn't just look at the domain name; it analyzes HTTP content, DNS records, and WHOIS information.

Smart Scoring: Uses a scoring system based on multiple factors (password forms, domain age, suspicious keywords) to determine a site's risk level.

Instant Telegram Alerts: Sends an immediate, richly-formatted, and detailed Telegram message for every suspicious domain detected.

Interactive Bot Interface: Easily manageable via Telegram commands (/tara, /durdur, /bilgi) and inline buttons.

Continuous & One-Time Scans: Capable of performing both on-demand single scans and running in a 24/7 continuous monitoring mode.

Detailed Logging: Logs all operations to monitor.log and archives all suspicious findings in found_suspicious_domains.txt.

📸 Example Alert
When the bot finds a suspicious domain, it sends a detailed report to the group, like this:

🔴 *SUSPICIOUS DOMAIN DETECTED*
━━━━━━━━━━━━━━━━━━━━━━━━━━━

🌐 *Domain:*
`examplesite-login.com`

📊 *Risk Level:* CRITICAL
📈 *Security Score:* 14/20
🔗 *IP Address:* `123.45.67.89`

🌐 *WEB INFORMATION*
━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔗 *Full URL:*
`https_//examplesite-login.com/login/auth.php`

📄 *Page Title:*
_Log in to your Bank Account_

📋 *WHOIS INFORMATION*
━━━━━━━━━━━━━━━━━━━━━━━━━━━
📅 *Creation Date:* 01 November 2025
⏳ *Domain Age:* 1 day ⚠️ *VERY NEW*

⚠️ *REASONS FOR DETECTION*
━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Password input form detected
2. Suspicious keyword in title: login
3. Very new domain (1 day)
4. Suspicious path in URL: login, auth

🕐 *Detection Time:*
02 November 2025, 18:00:00
🛠️ Installation
Follow these steps to get the project running:

1. Clone the Project:

Bash

git clone https://github.com/Raxiezzers/telegram-phishing-domain-detector.git
cd telegram-phishing-domain-detector

2. (Recommended) Create a Virtual Environment:

Bash

python -m venv venv
Linux/macOS: source venv/bin/activate

Windows: .\venv\Scripts\activate

3. Install Dependencies: Install all required Python libraries using the requirements.txt file.

Bash

pip install -r requirements.txt
⚙️ Configuration
To run the bot, you need two key pieces of information: a Telegram Bot Token and a Group Chat ID.

1. Get Your Telegram Bot Token:

Start a chat with @BotFather on Telegram.

Send the /newbot command and follow the prompts to set a name and username for your bot.

BotFather will give you an API token (e.g., 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11). Copy this token.

2. Get Your Group Chat ID:

Add the bot you just created to your target Telegram group.

Promote the bot to an administrator in the group.

Send any message to the group.

The easiest way to find the Chat ID is to add a bot like @userinfobot to the group, or to visit the following URL in your browser (replace <YOUR_TOKEN> with your token): https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates

Look for the chat object in the response. The ID will be a negative number starting with -100....

3. Edit the Code: Open the monitor_bot.py file and fill in the configuration section at the top with your credentials:

Python

# ------------- YAPILANDIRMA - BURAYI DÜZENLE! -------------
TELEGRAM_TOKEN = "YOUR_BOT_TOKEN_HERE"
GROUP_CHAT_ID = "-100YOUR_GROUP_ID_HERE"
# ---------------------------------------------------------
🚀 How to Run
1. Create Your Domain List: Create a file named domains.txt in the main project directory. Add the domains you want to monitor, one per line.

Example domains.txt content:

google.com
example-bank-login.com
facebook.com
my-site.net
login-account-verify.org
2. Start the Bot: Run the bot from your terminal using the following command:

Bash

python monitor_bot.py
If successful, you will see a "BOT ÇALIŞIYOR!" (BOT IS RUNNING!) message in your terminal.

🤖 Bot Commands
You can manage the bot from your Telegram group using these commands (Admin-only):

/start or /baslat: Starts the bot and shows basic info.

/tara: Performs a one-time scan of the domains.txt list.

/surekli_tarama: Configures the continuous scan mode (scans run back-to-back or with an interval).

/durdur: Stops the currently active scan.

/bilgi: Shows the current status of the scan (progress, found, ETA, etc.).

/istatistik: Displays general statistics, like total detections and top-ranked dangerous domains.

/gecmis: Lists the last 10 suspicious domains detected.

/yardim or /help: Shows a list of all commands and their descriptions.

⚖️ License
This project is licensed under the MIT License. See the LICENSE file for details.

⚠️ Disclaimer
This tool is created for cybersecurity research and educational purposes only. The user is solely responsible for any and all actions taken with this tool. Usage for illegal activities is strictly prohibited.
