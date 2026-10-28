# 🎣 Phishing Awareness Trainer

A desktop GUI application built with **Python and Tkinter** that teaches users how to identify phishing emails, fake websites, and social engineering attacks — with an interactive URL checker and a scored quiz.

> Built as a cybersecurity education project. No external dependencies required beyond Python's standard library.

---

## ✨ Features

| Tab | What it does |
|---|---|
| **Home** | Displays your quiz history, best/last scores, and a rotating security tip |
| **Lessons** | Five in-depth lessons on phishing techniques, fake websites, social engineering, real-world cases, and best practices |
| **URL Checker** | Paste any URL to get an instant risk score with detailed findings |
| **Quiz** | Five scenario-based questions with instant feedback and a progress bar |

### 🔍 URL Checker — what it detects

- Raw IP addresses in place of a domain name
- Unencrypted HTTP on sign-in pages
- `@` symbol in the address (browsers discard everything before it)
- Punycode / IDN homograph domains (`xn--`)
- Suspicious TLDs (`.zip`, `.top`, `.xyz`, `.tk`, `.ml`, etc.)
- Brand names in subdomains on unofficial domains (PayPal, Microsoft, Google, Apple, Amazon, SBI, HDFC, IRCTC, and more)
- Lookalike domain names (`paypa1`, `g00gle`) via homoglyph normalisation
- Fuzzy brand name matching (`SequenceMatcher` ratio ≥ 0.8)
- Sensitive keywords in the URL path (`login`, `verify`, `otp`, `kyc`, `refund`, etc.)
- Excessive hyphens and deep subdomain nesting

Risk is scored and displayed as **LOW RISK**, **SUSPICIOUS**, or **HIGH RISK** with a progress bar and a per-finding breakdown.

---

## 🖥️ Screenshots

> *(Add screenshots of the Home, Checker, and Quiz tabs here)*

---

## 🗂️ Project Structure

```
.
├── server.py        # Full application — GUI + URL analysis logic
└── README.md
```

The URL analysis logic (`analyse_url`, `registrable_domain`) is separated from the GUI class and can be imported and tested independently.

---

## ⚙️ Requirements

- Python 3.8 or later
- Tkinter (included with most Python installations)

### Installing Tkinter if it is missing

**Debian / Ubuntu**
```bash
sudo apt install python3-tk
```

**Fedora / RHEL**
```bash
sudo dnf install python3-tkinter
```

**macOS (Homebrew Python)**
```bash
brew install python-tk
```

**Windows** — Tkinter is bundled with the official Python installer from python.org.

---

## 🚀 Usage

```bash
python3 server.py
```

Or on Windows:
```
python server.py
```

No `pip install` needed — the app uses only the Python standard library (`tkinter`, `json`, `re`, `difflib`, `urllib.parse`, `pathlib`, `random`, `datetime`).

---

## 🧩 How it works

### URL risk scoring

Each URL is parsed with `urllib.parse.urlparse`. A set of heuristic checks each add points to a running total:

| Finding | Points |
|---|---|
| Raw IP address | 40 |
| Brand name in a non-official domain | 40 |
| `@` in the netloc | 35 |
| Fuzzy brand lookalike (≥ 80 % similarity) | 35 |
| Punycode / IDN domain | 25 |
| Suspicious TLD | 20 |
| Sensitive keywords in path | 15 |
| Unencrypted HTTP | 10 |
| Multiple hyphens in domain | 10 |
| Deep subdomain nesting (≥ 3 extra levels) | 10 |
| Digits mixed with letters in domain | 5 |

**Score ≥ 50 → HIGH RISK · Score ≥ 20 → SUSPICIOUS · Score < 20 → LOW RISK**

### Quiz and history

Quiz results are persisted as JSON at `~/.phishing_trainer_history.json` (up to 100 most recent attempts). The Home tab reads this file on every refresh to display attempt count, best score, and last score.

---

## 📚 Lesson content

1. **Phishing emails** — sender spoofing, urgency triggers, attachment types, hover-to-preview habit
2. **Fake websites** — how to read a domain right-to-left, digit substitutions, padlock misconceptions
3. **Social engineering** — urgency, authority, pretexting, vishing, smishing, baiting
4. **Real-world cases** — RSA SecurID (2011), Fake invoice fraud at Google & Facebook, Twitter hack (2020)
5. **Best practices** — MFA, password managers, reporting, password change after a credential compromise

---

## 📋 Supported brands (URL checker)

PayPal · Microsoft · Google · Apple · Amazon · Netflix · Facebook · Instagram · WhatsApp · Paytm · SBI · HDFC · ICICI · IRCTC · UIDAI

To add your own organisation's domains, extend the `BRANDS` dictionary at the top of `server.py`.

---

## ⚠️ Disclaimer

This tool is for **educational purposes only**. The URL checker is a heuristic aid — it can produce false positives and false negatives. Always verify important links through a channel you already trust.

---

## 👨‍💻 Author

> *(Add your name, college, and year here)*

---

## 📄 License

This project is for academic / educational use.
