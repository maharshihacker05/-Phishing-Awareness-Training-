#!/usr/bin/env python3
"""
Phishing Awareness Trainer - GUI edition
----------------------------------------
Desktop app built with Tkinter (included with most Python installs).

Tabs:
  Home     - your scores, a saved history, and a rotating security tip
  Lessons  - phishing emails, fake websites, social engineering, real cases, best practices
  Checker  - paste a web address and get a risk score with explanations
  Quiz     - scenario-based questions with instant feedback and a progress bar

Run:  python3 phishing_trainer_gui.py
Needs Python 3.8+. On Debian/Ubuntu, if tkinter is missing:  sudo apt install python3-tk
"""

import datetime
import difflib
import json
import random
import re
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from urllib.parse import urlparse

HISTORY_FILE = Path.home() / ".phishing_trainer_history.json"

RED = "#b3261e"
GREEN = "#2d6a4f"
AMBER = "#9a5b00"
GREY = "#5b616d"

# Official domains for brands the checker knows about. Extend for your organisation.
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "office.com"],
    "google": ["google.com", "gmail.com", "googleapis.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "paytm": ["paytm.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
}

MULTI_PART_SUFFIXES = {"co.uk", "co.in", "com.au", "co.jp", "gov.in", "ac.in", "org.in", "net.in", "co.za", "com.br", "gov.uk"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "live", "support", "icu", "rest"}
SENSITIVE_WORDS = {"login", "signin", "sign-in", "verify", "verification", "secure", "account", "update",
                   "confirm", "wallet", "suspend", "unlock", "banking", "kyc", "reset", "otp", "validate", "refund"}
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})

LESSONS = [
    ("Phishing emails", """Phishing emails often share these traits:

- A sender domain that does not match the company it claims to be from.
- Manufactured urgency: "act within 2 hours", "account suspended".
- Requests to log in or "verify" through a link.
- Isolation: "do not contact your manager".
- Generic greetings such as "Dear user" instead of your name.
- Unexpected attachments, especially macros, ZIP files and HTML files.
- Invoice or payment-detail changes from suppliers you did not expect.

Habit: hover over a link to see its real destination before you click."""),

    ("Fake websites", """Read a domain from RIGHT to LEFT. The owner is the registered domain just before the first single slash.

  https://login.microsoftonline.com/          -> owned by Microsoft
  https://login.microsoftonline.com.evil.net  -> owned by evil.net

Watch for:
- Brand names placed in subdomains.
- Digit substitutions such as paypa1 or g00gle.
- Extra hyphens and long random strings.
- Raw IP addresses in place of a domain name.
- A padlock icon, which only shows the connection is encrypted.

Good habit: type the address yourself or use a bookmark."""),

    ("Social engineering", """Attackers manipulate people rather than machines.

- Urgency and fear: shrink the time you have to think.
- Authority: pose as a CEO, a bank, the government or IT.
- Pretexting: invent a believable reason to make contact.
- Reciprocity and curiosity: offer a refund, a shared file or a secret.
- Vishing and smishing: the same playbook by phone call or text.
- Baiting: a labelled USB stick, or a fake support call.

Attackers rarely need clever code when a convincing story will do."""),

    ("Real-world cases", """2011: RSA SecurID. A booby-trapped spreadsheet sent to employees led to compromised token data, and tokens had to be replaced for customers.

2015 to 2017: Fake invoices. A fraudster impersonating an Asian hardware supplier got Google and Facebook finance staff to pay over 100 million US dollars in total.

2020: Twitter. Staff were phoned by people posing as IT, gave up access, and high-profile accounts were taken over.

Lesson: a payment request that changes how money is sent is a phishing request until verified through a channel you already trust."""),

    ("Best practices", """1. Verify requests through a second channel you already trust.
2. Go to the source yourself rather than following links.
3. Use multi-factor authentication, preferably passkeys or security keys.
4. Never share one-time codes with anyone, including "support".
5. Pause when you feel rushed. That is the signal to slow down.
6. Report suspicious messages to your security team.
7. Keep software and browsers updated.
8. Use a password manager. It will not autofill on lookalike sites.
9. If you entered a password on a fake page: change it immediately, end other sessions, and tell IT now."""),
]

QUIZ = [
    {
        "prompt": "A message from 'Payroll' says your direct deposit details changed and asks you to confirm via a link. What do you do?",
        "choices": [
            "Click the link and confirm the details.",
            "Ignore the email and contact Payroll through a number or portal you already use.",
            "Reply asking whether the email is genuine.",
        ],
        "answer": 1,
        "explanation": "Verify through a channel you already trust. Replying confirms your address is active and may reach the attacker.",
    },
    {
        "prompt": "Which web address belongs to Microsoft?",
        "choices": [
            "https://microsoft.com.account-check.net/login",
            "https://microsoft-login.verify.co/",
            "https://login.microsoftonline.com/",
        ],
        "answer": 2,
        "explanation": "Only the last one is owned by Microsoft. The others have their real owner at the end of the domain.",
    },
    {
        "prompt": "A caller from your bank's fraud team knows your name and asks you to read out a code to 'cancel a suspicious payment'. What do you do?",
        "choices": [
            "Read out the code, since they know your name.",
            "Refuse to share the code, end the call, and phone the number on the back of your card.",
            "Ask them to send the code to a different phone number.",
        ],
        "answer": 1,
        "explanation": "Knowing your name proves nothing. A one-time code given to a caller hands over your account.",
    },
    {
        "prompt": "Your CEO emails from a personal-looking address asking you to urgently buy five gift cards and send the codes. What do you do?",
        "choices": [
            "Do not buy them. Verify through a known channel and report the message.",
            "Buy them quietly so the CEO is not disturbed.",
            "Buy one now and ask the rest of the questions later.",
        ],
        "answer": 0,
        "explanation": "Gift card requests combined with urgency and secrecy are a classic scam.",
    },
    {
        "prompt": "You entered your password on a page you now suspect is fake. What is the best first action?",
        "choices": [
            "Wait and see whether anything happens.",
            "Delete the email so it cannot be found.",
            "Change that password immediately, end other sessions, and report it now.",
        ],
        "answer": 2,
        "explanation": "Speed limits damage. Change the password, end sessions, and report quickly.",
    },
]

TIPS = [
    "Hover over a link before clicking. The real destination appears in the status bar.",
    "Your bank will never ask you to read out a one-time code over the phone.",
    "Use a password manager. It will not autofill on a lookalike domain.",
    "Urgency is a warning sign. Legitimate deadlines rarely arrive as a surprise.",
    "Passkeys and security keys resist phishing better than SMS codes.",
    "If you clicked and entered details, act within minutes: change the password and report it.",
]


# ---------------------------------------------------------------------------
# Logic (no GUI here, so it can be tested on its own)
# ---------------------------------------------------------------------------

def registrable_domain(host):
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def analyse_url(raw):
    """Return (score, verdict, findings). findings is a list of (points, message)."""
    text = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
        text = "https://" + text
    parsed = urlparse(text)
    host = (parsed.hostname or "").lower().rstrip(".")
    path = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    findings = []

    def done():
        score = sum(p for p, _ in findings)
        if score >= 50:
            verdict = "HIGH RISK"
        elif score >= 20:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LOW RISK"
        return score, verdict, findings

    if not host:
        findings.append((0, "Could not read a hostname from this input."))
        return done()

    if parsed.scheme == "http":
        findings.append((10, "Uses unencrypted HTTP. Real sign-in pages use HTTPS."))
    if "@" in parsed.netloc:
        findings.append((35, "Contains '@' in the address. Browsers ignore everything before it."))
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        findings.append((40, "Raw IP address instead of a domain name."))
        return done()

    labels = host.split(".")
    domain = registrable_domain(host)
    owner_label = domain.split(".")[0]

    if "xn--" in host:
        findings.append((25, "Punycode domain (xn--) may imitate other characters."))
    if labels[-1] in SUSPICIOUS_TLDS:
        findings.append((20, f"'.{labels[-1]}' is a domain ending often abused by scammers."))

    official = any(host == o or host.endswith("." + o) for owners in BRANDS.values() for o in owners)
    if not official:
        norm_host = host.translate(HOMOGLYPHS).replace("-", "")
        norm_label = owner_label.translate(HOMOGLYPHS).replace("-", "")
        for brand in BRANDS:
            if brand in norm_host:
                findings.append((40, f"Contains the brand '{brand}' but is not an official {brand} domain."))
                break
            if difflib.SequenceMatcher(None, norm_label, brand).ratio() >= 0.8:
                findings.append((35, f"'{owner_label}' looks like a misspelling of '{brand}'."))
                break
        hits = sorted(w for w in SENSITIVE_WORDS if w in path.lower())
        if hits:
            findings.append((15, f"Sensitive words in the link ({', '.join(hits)}) on an unknown domain."))

    if owner_label.count("-") >= 2:
        findings.append((10, "Several hyphens in the domain name."))
    if len(labels) - len(domain.split(".")) >= 3:
        findings.append((10, "Many subdomain levels can hide the real owner."))
    if re.search(r"\d", owner_label) and re.search(r"[a-z]", owner_label):
        findings.append((5, "Digits mixed into the domain name."))

    if not findings:
        findings.append((0, f"No obvious red flags. The owner appears to be {domain}. Still verify important sites."))
    return done()


def load_history():
    try:
        return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def save_history(entries):
    try:
        HISTORY_FILE.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    except OSError:
        pass  # history is a convenience; never crash over it


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class TrainerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Awareness Trainer")
        self.geometry("900x660")
        self.minsize(760, 540)

        self.style = ttk.Style(self)
        for theme in ("clam", "vista", "aqua"):
            if theme in self.style.theme_names():
                self.style.theme_use(theme)
                break
        self.style.configure("Title.TLabel", font=("TkDefaultFont", 18, "bold"))
        self.style.configure("Sub.TLabel", foreground=GREY)
        self.style.configure("Big.TLabel", font=("TkDefaultFont", 16, "bold"))
        self.style.configure("Head.TLabel", font=("TkDefaultFont", 12, "bold"))

        header = ttk.Frame(self, padding=(20, 14, 20, 6))
        header.pack(fill="x")
        ttk.Label(header, text="Phishing Awareness Trainer", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Learn to spot fake emails, fake websites and manipulation.",
                  style="Sub.TLabel").pack(anchor="w")

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=16, pady=(6, 16))

        self.home_tab = ttk.Frame(self.nb, padding=18)
        self.lessons_tab = ttk.Frame(self.nb, padding=12)
        self.checker_tab = ttk.Frame(self.nb, padding=18)
        self.quiz_tab = ttk.Frame(self.nb, padding=18)
        self.nb.add(self.home_tab, text="  Home  ")
        self.nb.add(self.lessons_tab, text="  Lessons  ")
        self.nb.add(self.checker_tab, text="  URL checker  ")
        self.nb.add(self.quiz_tab, text="  Quiz  ")

        self._build_home()
        self._build_lessons()
        self._build_checker()
        self._build_quiz()
        self._refresh_home()

    # ----- Home -----------------------------------------------------------
    def _build_home(self):
        f = self.home_tab
        ttk.Label(f, text="Welcome", style="Head.TLabel").pack(anchor="w")
        ttk.Label(f, text="Work through the lessons, test a link, then take the quiz. Your results are saved on this computer.",
                  style="Sub.TLabel", wraplength=800).pack(anchor="w", pady=(2, 14))

        stats = ttk.Frame(f)
        stats.pack(fill="x")
        self.stat_attempts = self._stat_box(stats, "Quizzes taken")
        self.stat_best = self._stat_box(stats, "Best score")
        self.stat_last = self._stat_box(stats, "Last score")

        ttk.Label(f, text="Recent attempts", style="Head.TLabel").pack(anchor="w", pady=(18, 4))
        self.history_text = tk.Text(f, height=8, width=60, relief="flat", wrap="word", state="disabled")
        self.history_text.pack(anchor="w", fill="x")

        btns = ttk.Frame(f)
        btns.pack(anchor="w", pady=10)
        ttk.Button(btns, text="Start quiz", command=lambda: self._go("quiz")).pack(side="left")
        ttk.Button(btns, text="Clear history", command=self._clear_history).pack(side="left", padx=8)

        ttk.Label(f, text="Tip of the moment", style="Head.TLabel").pack(anchor="w", pady=(14, 2))
        self.tip_var = tk.StringVar()
        ttk.Label(f, textvariable=self.tip_var, wraplength=800).pack(anchor="w")
        ttk.Button(f, text="Another tip", command=self._new_tip).pack(anchor="w", pady=8)
        self._new_tip()

    def _stat_box(self, parent, title):
        box = ttk.Frame(parent, padding=(0, 0, 28, 0))
        box.pack(side="left")
        ttk.Label(box, text=title, style="Sub.TLabel").pack(anchor="w")
        value = ttk.Label(box, text="-", style="Big.TLabel")
        value.pack(anchor="w")
        return value

    def _new_tip(self):
        self.tip_var.set(random.choice(TIPS))

    def _refresh_home(self):
        history = load_history()
        self.stat_attempts.config(text=str(len(history)))
        if history:
            scores = [h["score"] for h in history]
            self.stat_best.config(text=f"{max(scores)} / {len(QUIZ)}")
            self.stat_last.config(text=f"{history[-1]['score']} / {len(QUIZ)}")
        else:
            self.stat_best.config(text="-")
            self.stat_last.config(text="-")

        lines = []
        for h in reversed(history[-8:]):
            lines.append(f"{h['date']}    {h['score']} of {h['total']}")
        if not lines:
            lines = ["No attempts yet. Take the quiz to start your record."]
        self.history_text.config(state="normal")
        self.history_text.delete("1.0", "end")
        self.history_text.insert("1.0", "\n".join(lines))
        self.history_text.config(state="disabled")

    def _clear_history(self):
        if messagebox.askyesno("Clear history", "Delete all saved quiz results on this computer?"):
            save_history([])
            self._refresh_home()

    def _go(self, name):
        tabs = {"lessons": self.lessons_tab, "checker": self.checker_tab, "quiz": self.quiz_tab, "home": self.home_tab}
        self.nb.select(tabs[name])

    # ----- Lessons --------------------------------------------------------
    def _build_lessons(self):
        f = self.lessons_tab
        left = ttk.Frame(f)
        left.pack(side="left", fill="y", padx=(4, 12))
        ttk.Label(left, text="Topics", style="Head.TLabel").pack(anchor="w", pady=(0, 6))
        self.lesson_list = tk.Listbox(left, width=24, height=12, exportselection=False, activestyle="none")
        for title, _ in LESSONS:
            self.lesson_list.insert("end", title)
        self.lesson_list.pack(fill="y")
        self.lesson_list.bind("<<ListboxSelect>>", self._show_lesson)

        right = ttk.Frame(f)
        right.pack(side="left", fill="both", expand=True)
        self.lesson_title = ttk.Label(right, style="Head.TLabel")
        self.lesson_title.pack(anchor="w", pady=(0, 6))
        self.lesson_text = tk.Text(right, wrap="word", relief="flat", padx=6, pady=6, font=("TkDefaultFont", 11))
        self.lesson_text.pack(fill="both", expand=True)

        self.lesson_list.selection_set(0)
        self._show_lesson()

    def _show_lesson(self, _event=None):
        sel = self.lesson_list.curselection()
        idx = sel[0] if sel else 0
        title, body = LESSONS[idx]
        self.lesson_title.config(text=title)
        self.lesson_text.config(state="normal")
        self.lesson_text.delete("1.0", "end")
        self.lesson_text.insert("1.0", body)
        self.lesson_text.config(state="disabled")

    # ----- URL checker ----------------------------------------------------
    def _build_checker(self):
        f = self.checker_tab
        ttk.Label(f, text="Paste a web address", style="Head.TLabel").pack(anchor="w")
        ttk.Label(f, text="The checker looks for lookalike names, risky patterns and sensitive words. It is a warning aid, not proof.",
                  style="Sub.TLabel", wraplength=800).pack(anchor="w", pady=(2, 10))

        row = ttk.Frame(f)
        row.pack(fill="x")
        self.url_var = tk.StringVar()
        entry = ttk.Entry(row, textvariable=self.url_var, font=("TkFixedFont", 11))
        entry.pack(side="left", fill="x", expand=True, ipady=4)
        entry.bind("<Return>", lambda e: self._check_url())
        entry.focus_set()
        ttk.Button(row, text="Check", command=self._check_url).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Clear", command=self._clear_checker).pack(side="left", padx=(6, 0))

        samples = ttk.Frame(f)
        samples.pack(anchor="w", pady=8)
        ttk.Label(samples, text="Try:", style="Sub.TLabel").pack(side="left")
        for sample in ["login.microsoftonline.com", "paypa1-secure.com/login", "http://192.168.1.5/verify",
                       "paypal.com.account-check.net/signin"]:
            ttk.Button(samples, text=sample, command=lambda s=sample: self._use_sample(s)).pack(side="left", padx=4)

        result = ttk.Frame(f, padding=(0, 10, 0, 0))
        result.pack(fill="both", expand=True)
        self.verdict_label = ttk.Label(result, text="Enter a link above.", style="Big.TLabel")
        self.verdict_label.pack(anchor="w")
        self.meter = ttk.Progressbar(result, maximum=100, length=360)
        self.meter.pack(anchor="w", pady=6)
        self.findings_text = tk.Text(result, height=12, wrap="word", relief="flat", padx=6, pady=6,
                                     font=("TkDefaultFont", 11), state="disabled")
        self.findings_text.pack(fill="both", expand=True)
        self.findings_text.tag_configure("bad", foreground=RED)
        self.findings_text.tag_configure("ok", foreground=GREEN)
        self.findings_text.tag_configure("info", foreground=GREY)

    def _use_sample(self, text):
        self.url_var.set(text)
        self._check_url()

    def _clear_checker(self):
        self.url_var.set("")
        self.verdict_label.config(text="Enter a link above.", foreground="")
        self.meter["value"] = 0
        self.findings_text.config(state="normal")
        self.findings_text.delete("1.0", "end")
        self.findings_text.config(state="disabled")

    def _check_url(self):
        url = self.url_var.get().strip()
        if not url:
            return
        score, verdict, findings = analyse_url(url)
        color = {"HIGH RISK": RED, "SUSPICIOUS": AMBER}.get(verdict, GREEN)
        self.verdict_label.config(text=f"{verdict}  (score {score})", foreground=color)
        self.meter["value"] = min(score, 100)

        t = self.findings_text
        t.config(state="normal")
        t.delete("1.0", "end")
        for points, msg in findings:
            tag = "bad" if points >= 20 else ("info" if points == 0 else "ok")
            label = f"+{points}" if points else "info"
            t.insert("end", f"{label:>6}   {msg}\n", tag)
        t.insert("end", "\nTip: type the official address yourself instead of trusting any link.\n", "info")
        t.config(state="disabled")

    # ----- Quiz -----------------------------------------------------------
    def _build_quiz(self):
        f = self.quiz_tab
        top = ttk.Frame(f)
        top.pack(fill="x")
        self.q_counter = ttk.Label(top, style="Sub.TLabel")
        self.q_counter.pack(side="left")
        self.q_bar = ttk.Progressbar(top, maximum=100, length=300)
        self.q_bar.pack(side="right")

        self.q_prompt = ttk.Label(f, style="Head.TLabel", wraplength=780, justify="left")
        self.q_prompt.pack(anchor="w", pady=(16, 10))
        self.choice_frame = ttk.Frame(f)
        self.choice_frame.pack(anchor="w", fill="x")
        self.q_feedback = ttk.Label(f, wraplength=780, justify="left")
        self.q_feedback.pack(anchor="w", pady=(14, 0))
        self.q_action = ttk.Button(f, text="Check answer", command=self._check_answer)
        self.q_action.pack(anchor="w", pady=14)

        self._start_quiz()

    def _start_quiz(self):
        self.q_index = 0
        self.q_score = 0
        self._show_question()

    def _show_question(self):
        q = QUIZ[self.q_index]
        self.q_counter.config(text=f"Question {self.q_index + 1} of {len(QUIZ)}")
        self.q_bar["value"] = self.q_index / len(QUIZ) * 100
        self.q_prompt.config(text=q["prompt"])
        for w in self.choice_frame.winfo_children():
            w.destroy()
        self.selected = tk.IntVar(value=-1)
        for i, text in enumerate(q["choices"]):
            ttk.Radiobutton(self.choice_frame, text=text, value=i, variable=self.selected).pack(anchor="w", pady=4)
        self.q_feedback.config(text="", foreground="")
        self.q_action.config(text="Check answer", command=self._check_answer)

    def _check_answer(self):
        if self.selected.get() < 0:
            messagebox.showinfo("Choose an answer", "Please select one option first.")
            return
        q = QUIZ[self.q_index]
        chosen = self.selected.get()
        for w in self.choice_frame.winfo_children():
            w.state(["disabled"])
        if chosen == q["answer"]:
            self.q_score += 1
            self.q_feedback.config(text=f"Correct. {q['explanation']}", foreground=GREEN)
        else:
            self.q_feedback.config(
                text=f"Not quite. The right answer is: {q['choices'][q['answer']]}\n{q['explanation']}",
                foreground=RED)
        last = self.q_index == len(QUIZ) - 1
        self.q_action.config(text="See results" if last else "Next question", command=self._next_question)

    def _next_question(self):
        self.q_index += 1
        if self.q_index < len(QUIZ):
            self._show_question()
        else:
            self._finish_quiz()

    def _finish_quiz(self):
        total = len(QUIZ)
        history = load_history()
        history.append({
            "date": datetime.date.today().isoformat(),
            "score": self.q_score,
            "total": total,
        })
        save_history(history[-100:])
        self._refresh_home()

        self.q_bar["value"] = 100
        self.q_counter.config(text="Finished")
        for w in self.choice_frame.winfo_children():
            w.destroy()
        self.q_prompt.config(text=f"You scored {self.q_score} of {total}.")
        if self.q_score == total:
            msg = "Excellent. You caught every trap. Keep pausing and verifying."
        elif self.q_score >= total - 2:
            msg = "Good work. Review the explanations you missed in the Lessons tab."
        else:
            msg = "Worth another read. Verify through a trusted channel and report quickly."
        self.q_feedback.config(text=msg, foreground=GREEN if self.q_score >= total - 2 else AMBER)
        self.q_action.config(text="Retake quiz", command=self._start_quiz_again)

    def _start_quiz_again(self):
        self._start_quiz()


def main():
    app = TrainerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
