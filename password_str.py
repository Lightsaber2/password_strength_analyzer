import re
import math
import requests
import hashlib

# -------------------------------
# Common weak passwords dictionary (quick reference)
# -------------------------------
common_passwords = [
    "password", "123456", "123456789", "qwerty", "abc123", "111111", "123123",
    "password1", "iloveyou", "admin", "welcome", "monkey", "letmein"
]

# -------------------------------
# Load dictionary words (large list from dictionary.txt)
# -------------------------------
def load_dictionary(path="dictionary.txt"):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return set(word.strip().lower() for word in f if word.strip())
    except FileNotFoundError:
        print("⚠️ dictionary.txt not found — dictionary check disabled.")
        return set()

dictionary_words = load_dictionary()

# -------------------------------
# Function to calculate entropy
# -------------------------------
def calculate_entropy(password):
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # Approx symbols
    if pool == 0:
        return 0
    return round(math.log2(pool ** len(password)), 2)

# -------------------------------
# Check password strength
# -------------------------------
def check_strength(password):
    strength_points = 0
    feedback = []

    # Length check
    if len(password) < 8:
        feedback.append("❌ Too short (minimum 8 characters recommended).")
    else:
        strength_points += 1

    # Complexity checks
    if re.search(r"[a-z]", password):
        strength_points += 1
    else:
        feedback.append("❌ Add lowercase letters.")
    if re.search(r"[A-Z]", password):
        strength_points += 1
    else:
        feedback.append("❌ Add uppercase letters.")
    if re.search(r"[0-9]", password):
        strength_points += 1
    else:
        feedback.append("❌ Add numbers.")
    if re.search(r"[^a-zA-Z0-9]", password):
        strength_points += 1
    else:
        feedback.append("❌ Add special characters.")

    # Common password check
    if password.lower() in common_passwords:
        feedback.append("❌ Your password is a very common one, try something unique.")

    # Raw entropy calculation (baseline before penalties)
    entropy = calculate_entropy(password)

    # Dictionary word check (longest match logic)
    pw_lower = password.lower()
    longest_match = ""
    for word in dictionary_words:
        if len(word) >= 4 and word in pw_lower:
            if len(word) > len(longest_match):
                longest_match = word

    # Apply dictionary penalties
    if pw_lower in dictionary_words:
        feedback.append(
            "❌ Your password is simply a dictionary word. "
            "Try mixing random letters, numbers, and symbols for more strength."
        )
        entropy -= 20  # big penalty for being only a dictionary word
    elif longest_match:
        if len(password) <= 6:
            feedback.append(
                f"❌ Your password includes the word '{longest_match}', making it easy to guess. "
                "Short, word-based passwords are very weak."
            )
            entropy -= 20
        elif len(password) <= 10:
            feedback.append(
                f"⚠️ Your password includes the word '{longest_match}'. "
                "Words reduce unpredictability — a random mix of characters is safer."
            )
            entropy -= 10
        else:
            # password > 10 → no penalty, no feedback
            pass

    # Entropy floor safeguard
    if entropy < 0:
        entropy = 0

    # Final strength rating
    if strength_points <= 2 or len(password) < 8 or entropy < 30:
        rating = "Weak"
    elif strength_points == 3 or entropy < 50:
        rating = "Moderate"
    elif strength_points == 4 or entropy < 70:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return rating, entropy, feedback

# -------------------------------
# Optional: Check HaveIBeenPwned API
# -------------------------------
def check_breach(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    response = requests.get(url)
    if response.status_code != 200:
        return "⚠️ Could not check breach status."

    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f"❌ Found in breaches {count} times!"
    return "✅ Not found in known breaches."

# -------------------------------
# Main program (for testing only)
# -------------------------------
if __name__ == "__main__":
    password = input("Enter a password to analyze: ")

    rating, entropy, feedback = check_strength(password)

    print("\n🔐 Password Strength Analysis")
    print("-" * 40)
    print(f"Password Rating : {rating}")
    print(f"Entropy Score   : {entropy} bits")
    print("\nFeedback:")
    if feedback:
        for f in feedback:
            print(f"  {f}")
    else:
        print("  ✅ Good mix of characters!")

    # Breach check
    print("\nBreach Check:")
    print(check_breach(password))
