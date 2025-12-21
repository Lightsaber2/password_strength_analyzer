import re
import math
import requests
import hashlib

# -------------------------------
# Common weak passwords dictionary
# -------------------------------
common_passwords = [
    "password", "123456", "123456789", "qwerty", "abc123", "111111", "123123",
    "password1", "iloveyou", "admin", "welcome", "monkey", "letmein"
]

# -------------------------------
# Keyboard walk patterns
# -------------------------------
KEYBOARD_PATTERNS = [
    # QWERTY rows
    "qwerty", "asdfgh", "zxcvbn",
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    # Common walks
    "1qaz", "2wsx", "3edc", "4rfv",
    "qazwsx", "wsxedc", "edcrfv",
    # Numeric keypad
    "789456", "456123", "147258", "369258"
]

# -------------------------------
# Load dictionary words
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
# Pattern Detection Functions
# -------------------------------
def detect_repetition(password):
    """
    Detects character repetition patterns.
    Returns (has_repetition, penalty, description)
    """
    # Check for repeated characters (3+ times)
    repeat_pattern = re.search(r'(.)\1{2,}', password)
    if repeat_pattern:
        repeated_char = repeat_pattern.group(1)
        repeat_count = len(repeat_pattern.group(0))
        if repeat_count >= 4:
            return True, 15, f"Repeated character '{repeated_char}' {repeat_count} times"
        elif repeat_count == 3:
            return True, 10, f"Repeated character '{repeated_char}' 3 times"
    
    # Check for repeated sequences (e.g., "123123" or "abcabc")
    for length in range(2, len(password) // 2 + 1):
        for i in range(len(password) - length * 2 + 1):
            chunk = password[i:i+length]
            if password[i+length:i+length*2] == chunk:
                return True, 12, f"Repeated sequence '{chunk}'"
    
    return False, 0, None

def detect_sequences(password):
    """
    Detects sequential patterns (abc, 123, etc.)
    Returns (has_sequence, penalty, description)
    """
    pw_lower = password.lower()
    
    # Alphabetic sequences
    for i in range(len(pw_lower) - 2):
        if ord(pw_lower[i+1]) == ord(pw_lower[i]) + 1 and \
           ord(pw_lower[i+2]) == ord(pw_lower[i+1]) + 1:
            seq = pw_lower[i:i+3]
            # Check if sequence extends further
            seq_len = 3
            j = i + 3
            while j < len(pw_lower) and ord(pw_lower[j]) == ord(pw_lower[j-1]) + 1:
                seq_len += 1
                j += 1
            
            if seq_len >= 4:
                return True, 15, f"Alphabetic sequence of {seq_len} characters"
            else:
                return True, 10, f"Alphabetic sequence '{seq}'"
    
    # Numeric sequences
    for i in range(len(password) - 2):
        if password[i:i+3].isdigit():
            nums = [int(password[i]), int(password[i+1]), int(password[i+2])]
            if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                # Check if sequence extends
                seq_len = 3
                j = i + 3
                while j < len(password) and password[j].isdigit() and \
                      int(password[j]) == int(password[j-1]) + 1:
                    seq_len += 1
                    j += 1
                
                if seq_len >= 4:
                    return True, 15, f"Numeric sequence of {seq_len} digits"
                else:
                    return True, 10, f"Numeric sequence '{password[i:i+3]}'"
    
    return False, 0, None

def detect_keyboard_walk(password):
    """
    Detects keyboard walk patterns
    Returns (has_walk, penalty, description)
    """
    pw_lower = password.lower()
    
    for pattern in KEYBOARD_PATTERNS:
        if pattern in pw_lower:
            return True, 12, f"Keyboard pattern '{pattern}' detected"
        # Check reverse
        if pattern[::-1] in pw_lower:
            return True, 12, f"Reverse keyboard pattern '{pattern[::-1]}' detected"
    
    return False, 0, None

def detect_date_patterns(password):
    """
    Detects common date-related patterns with realistic constraints.
    Returns (has_date, penalty, description)
    """
    date_patterns = [
        # Likely birth years (1950–2049)
        (r'(19[5-9]\d|20[0-4]\d)', "likely birth year"),

        # Common date formats
        (r'\b\d{2}[/-]\d{2}[/-]\d{2,4}\b', "date format (DD/MM/YYYY)"),

        # Compact YYYYMMDD
        (r'\b(19[5-9]\d|20[0-4]\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\b',
         "compact date (YYYYMMDD)")
    ]

    for pattern, description in date_patterns:
        if re.search(pattern, password):
            return True, 8, f"Date pattern detected ({description})"

    return False, 0, None


# -------------------------------
# Calculate entropy
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
        pool += 32
    if pool == 0:
        return 0
    return round(math.log2(pool ** len(password)), 2)

# -------------------------------
# Crack time estimation
# -------------------------------
def estimate_crack_time(entropy, attack_speed=10_000_000_000):
    """
    Estimate time to crack based on entropy.
    
    Args:
        entropy: Password entropy in bits
        attack_speed: Guesses per second (default: 10 billion for offline attack)
    
    Returns:
        Human-readable time string
    """
    if entropy <= 0:
        return "Instantly"
    
    # Calculate total possible combinations
    attempts = 2 ** entropy
    
    # Average time to crack (50% of keyspace)
    seconds = attempts / (2 * attack_speed)
    
    # Convert to human-readable format
    if seconds < 1:
        return "Less than 1 second"
    elif seconds < 60:
        return f"~{int(seconds)} seconds"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"~{minutes} minute{'s' if minutes != 1 else ''}"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"~{hours} hour{'s' if hours != 1 else ''}"
    elif seconds < 31536000:
        days = int(seconds / 86400)
        return f"~{days} day{'s' if days != 1 else ''}"
    elif seconds < 31536000 * 100:
        years = int(seconds / 31536000)
        return f"~{years} year{'s' if years != 1 else ''}"
    elif seconds < 31536000 * 1000:
        return f"~{int(seconds / 31536000)} centuries"
    else:
        return "Multiple millennia"

# -------------------------------
# Enhanced strength check with patterns
# -------------------------------
def check_strength(password):
    strength_points = 0
    feedback = []
    pattern_penalties = []

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

    # Calculate base entropy
    entropy = calculate_entropy(password)

    # Pattern detection and penalties
    total_pattern_penalty = 0
    
    # Check repetition
    has_rep, rep_penalty, rep_desc = detect_repetition(password)
    if has_rep:
        feedback.append(f"⚠️ Weak pattern: {rep_desc}")
        pattern_penalties.append(("Repetition", rep_penalty))
        total_pattern_penalty += rep_penalty
    
    # Check sequences
    has_seq, seq_penalty, seq_desc = detect_sequences(password)
    if has_seq:
        feedback.append(f"⚠️ Weak pattern: {seq_desc}")
        pattern_penalties.append(("Sequence", seq_penalty))
        total_pattern_penalty += seq_penalty
    
    # Check keyboard walks
    has_walk, walk_penalty, walk_desc = detect_keyboard_walk(password)
    if has_walk:
        feedback.append(f"⚠️ Weak pattern: {walk_desc}")
        pattern_penalties.append(("Keyboard walk", walk_penalty))
        total_pattern_penalty += walk_penalty
    
    # Check date patterns
    has_date, date_penalty, date_desc = detect_date_patterns(password)
    if has_date:
        feedback.append(f"⚠️ Weak pattern: {date_desc}")
        pattern_penalties.append(("Date pattern", date_penalty))
        total_pattern_penalty += date_penalty

    # Dictionary check with longest match
    pw_lower = password.lower()
    longest_match = ""
    for word in dictionary_words:
        if len(word) >= 4 and word in pw_lower:
            if len(word) > len(longest_match):
                longest_match = word

    # Dictionary penalties
    if pw_lower in dictionary_words:
        feedback.append(
            "❌ Your password is simply a dictionary word. "
            "Try mixing random letters, numbers, and symbols."
        )
        entropy -= 20
    elif longest_match:
        if len(password) <= 6:
            feedback.append(
                f"❌ Contains dictionary word '{longest_match}'. "
                "Short word-based passwords are very weak."
            )
            entropy -= 20
        elif len(password) <= 10:
            feedback.append(
                f"⚠️ Contains dictionary word '{longest_match}'. "
                "Words reduce unpredictability."
            )
            entropy -= 10

    # Apply pattern penalties to entropy
    entropy -= total_pattern_penalty

    # Entropy floor
    if entropy < 0:
        entropy = 0

    # Estimate crack time
    crack_time = estimate_crack_time(entropy)
    crack_time_fast = estimate_crack_time(entropy, attack_speed=100_000_000_000)

    # Final strength rating
    if strength_points <= 2 or len(password) < 8 or entropy < 30:
        rating = "Weak"
    elif strength_points == 3 or entropy < 50:
        rating = "Moderate"
    elif strength_points == 4 or entropy < 70:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return rating, entropy, feedback, crack_time, crack_time_fast, pattern_penalties

# -------------------------------
# Check breach status
# -------------------------------
def check_breach(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return "⚠️ Could not check breach status."

        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return f"❌ Found in breaches {count} times!"
        return "✅ Not found in known breaches."
    except:
        return "⚠️ Could not check breach status."

# -------------------------------
# CLI testing
# -------------------------------
if __name__ == "__main__":
    password = input("Enter a password to analyze: ")

    rating, entropy, feedback, crack_time, crack_time_fast, pattern_penalties = check_strength(password)

    print("\n🔐 Password Strength Analysis")
    print("-" * 60)
    print(f"Password Rating    : {rating}")
    print(f"Effective Entropy  : {entropy} bits")
    print(f"\n⏱️  Crack Time Estimates:")
    print(f"  Offline attack (10B guesses/sec)  : {crack_time}")
    print(f"  Fast GPU attack (100B guesses/sec): {crack_time_fast}")
    
    if pattern_penalties:
        print(f"\n⚠️  Pattern Penalties Applied:")
        for pattern_type, penalty in pattern_penalties:
            print(f"  • {pattern_type}: -{penalty} bits")

    print("\n📋 Feedback:")
    if feedback:
        for f in feedback:
            print(f"  {f}")
    else:
        print("  ✅ Excellent password strength!")

    print("\n🔍 Breach Check:")
    print(f"  {check_breach(password)}")