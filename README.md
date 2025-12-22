# Password Strength Analyzer

A security-focused password analysis tool that evaluates password strength using **real-world attack heuristics** rather than simplistic length or character checks.

This project models how passwords are actually attacked (rule-based cracking, optimized guesses, and leaked credential reuse) and presents the results in a clear, educational way.

---

## 🔍 What This Tool Does

Instead of just saying *“strong”* or *“weak”*, the analyzer answers:

> **How would this password realistically fail if an attacker tried to crack it?**

It combines entropy analysis, pattern detection, and breach intelligence to give actionable feedback.

---

## ✨ Features

### Core Analysis
- Length and character diversity checks (upper, lower, digits, symbols)
- Entropy calculation to measure unpredictability
- Dictionary word detection (full and partial matches)

### Pattern-Based Penalties
Detects and penalizes common human-chosen password patterns:
- Repeated characters and sequences (`aaa`, `abcabc`)
- Sequential patterns (`abcd`, `1234`)
- Keyboard walks (`qwerty`, `1qaz`, numeric keypad paths)
- Date-based patterns (birth years, formatted dates)

> These patterns significantly reduce the effective search space used by real attackers.

### Crack-Time Estimation
Estimates **average time to crack** based on adjusted entropy:
- Offline attack (~10B guesses/sec)
- Fast GPU attack (~100B guesses/sec)

Results are shown in human-readable time (seconds → years → millennia).

### Breach Intelligence
- Integrates with the **Have I Been Pwned** k-anonymity API
- Passwords are **never sent in plaintext**
- Detects if a password has appeared in known data breaches

### Web Interface
- Clean Flask-based UI
- Visual strength bar
- Explicit display of pattern penalties
- Fully supported dark mode

---

## 📦 Project Structure

```
password_strength_analyzer/
│── app.py                # Flask application entry point
│── password_str.py       # Core analysis and attack modeling logic
│── dictionary.txt        # Dictionary words for pattern detection
│── templates/
│    └── index.html       # Web UI (light + dark mode)
│── requirements.txt      # Python dependencies
│── LICENSE               # MIT License
│── README.md             # Project documentation
```

---

## 🚀 Installation

### 1. Clone the repository
```bash
git clone https://github.com/Lightsaber2/password_strength_analyzer.git
cd password_strength_analyzer
```

### 2. Create a virtual environment (recommended)
```bash
python -m venv .venv
source .venv/bin/activate      # Linux / macOS
.venv\Scripts\activate       # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

### Run the web application
```bash
python app.py
```

Then open your browser at:
```
http://127.0.0.1:5000
```

Enter a password to receive:
- Strength rating
- Effective entropy
- Crack-time estimates
- Pattern penalty breakdown
- Breach status

---

## 🧠 Design Notes

- Entropy values are **heuristically adjusted** to reflect real-world cracking optimizations.
- Pattern penalties approximate how attackers reduce keyspace using rules and masks.
- Crack-time estimates assume **average-case** attack success (50% of keyspace).
- This tool is intended for **educational and defensive use** only.

---

## 🛡️ Security Considerations

- Passwords are processed in-memory only
- No password storage or logging
- Breach checks use SHA-1 prefix k-anonymity
- Suitable for learning, demos, and portfolio use

---

## 📄 License

This project is licensed under the **MIT License**.
See the `LICENSE` file for details.
