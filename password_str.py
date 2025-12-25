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
# Adaptive Feedback Helper Functions
# -------------------------------
def analyze_number_placement(password):
    """Analyze where numbers are placed in the password"""
    if not re.search(r"[0-9]", password):
        return None
    
    # Check if numbers are only at the end
    if re.search(r'^[^0-9]+[0-9]+$', password):
        return "end"
    # Check if numbers are only at the beginning
    elif re.search(r'^[0-9]+[^0-9]+$', password):
        return "start"
    else:
        return "mixed"

def analyze_symbol_placement(password):
    """Analyze where symbols are placed in the password"""
    if not re.search(r"[^a-zA-Z0-9]", password):
        return None
    
    # Check if symbols are only at the end
    if re.search(r'^[a-zA-Z0-9]+[^a-zA-Z0-9]+$', password):
        return "end"
    # Check if symbols are only at the beginning
    elif re.search(r'^[^a-zA-Z0-9]+[a-zA-Z0-9]+$', password):
        return "start"
    else:
        return "mixed"

def analyze_case_pattern(password):
    """Analyze capitalization patterns"""
    if not re.search(r"[a-zA-Z]", password):
        return None
    
    # Check if only first letter is capitalized
    if re.match(r'^[A-Z][a-z]*', password) and not re.search(r'[A-Z]', password[1:]):
        return "first_only"
    # Check if all caps
    elif password.isupper():
        return "all_caps"
    # Check if alternating
    elif re.search(r'([a-z][A-Z]|[A-Z][a-z]){2,}', password):
        return "alternating"
    else:
        return "mixed"

def get_adaptive_feedback(password, has_lower, has_upper, has_digit, has_symbol, length):
    """
    Generate adaptive, context-aware feedback that explains vulnerabilities
    and provides actionable guidance.
    """
    feedback = []
    
    # Length analysis with context
    if length < 8:
        feedback.append(
            "❌ Too short (< 8 characters): Attackers can try every possible combination "
            "in seconds with modern hardware. Aim for at least 12 characters to make "
            "brute-force attacks computationally infeasible."
        )
    elif length < 12:
        feedback.append(
            "⚠️ Length could be stronger: While 8+ characters meet minimum requirements, "
            "12+ characters dramatically increase crack time. Each additional character "
            "multiplies the search space attackers must explore."
        )
    
    # Analyze number placement
    num_placement = analyze_number_placement(password)
    if not has_digit:
        feedback.append(
            "❌ Missing numbers: Passwords without digits have a smaller character set, "
            "reducing entropy. However, don't just add '123' or '1' at the end—attackers "
            "expect this. Instead, insert digits throughout the password (e.g., 'h3llo' or 'pass7word9')."
        )
    elif num_placement == "end":
        feedback.append(
            "⚠️ Numbers only at the end: Attackers use 'append rules' that automatically "
            "try adding digits 0-999 to the end of common words. Try scattering numbers "
            "throughout: 'pa5sword' instead of 'password5'."
        )
    elif num_placement == "start":
        feedback.append(
            "⚠️ Numbers only at the beginning: Similar to ending with numbers, prepending "
            "digits is a common pattern attackers exploit. Distribute numbers throughout "
            "the password for better security."
        )
    
    # Analyze symbol placement
    sym_placement = analyze_symbol_placement(password)
    if not has_symbol:
        feedback.append(
            "❌ Missing special characters: Adding symbols ($, @, !, etc.) increases "
            "the character pool and entropy. But avoid predictable substitutions like "
            "'@' for 'a' or '!' at the end. Try weaving symbols naturally: 'my$ecret#pass'."
        )
    elif sym_placement == "end":
        feedback.append(
            "⚠️ Symbol only at the end: Appending '!' or '!' is extremely common—cracking "
            "tools specifically check for this. Place symbols in the middle or use multiple "
            "symbols in different positions."
        )
    elif sym_placement == "start":
        feedback.append(
            "⚠️ Symbol only at the beginning: Starting with a symbol is less common than "
            "ending with one, but still predictable. Mix symbols throughout for stronger security."
        )
    
    # Analyze case patterns
    case_pattern = analyze_case_pattern(password)
    if not has_lower and not has_upper:
        pass  # No letters at all - handled elsewhere
    elif not has_upper:
        feedback.append(
            "❌ All lowercase: Passwords without uppercase letters are easier to crack "
            "because the search space is smaller. Add capitals, but not just the first letter—"
            "that's what everyone does. Try: 'passWord' or 'pAsswoRd' instead of 'Password'."
        )
    elif not has_lower:
        feedback.append(
            "❌ All uppercase: While uncommon, all-caps passwords don't add much security "
            "and are predictable. Mix uppercase and lowercase unpredictably throughout."
        )
    elif case_pattern == "first_only":
        feedback.append(
            "⚠️ Only first letter capitalized: This is the default capitalization pattern "
            "most people use. Cracking tools automatically test this variation first. "
            "Capitalize letters in unexpected places: 'paSsWord' or 'passWorD'."
        )
    elif case_pattern == "all_caps":
        feedback.append(
            "⚠️ All capitals: While technically adding complexity, all-caps is easy to "
            "detect and try. Vary your capitalization naturally."
        )
    
    return feedback

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
            return (True, 15, 
                    f"Repeated '{repeated_char}' × {repeat_count}: Repetition drastically reduces "
                    f"effective password space. Attackers use compression techniques that treat "
                    f"repeated characters as a single pattern.")
        elif repeat_count == 3:
            return (True, 10, 
                    f"Repeated '{repeated_char}' × 3: Even short repetitions are flagged by "
                    f"pattern-matching attacks. Vary your characters.")
    
    # Check for repeated sequences (e.g., "123123" or "abcabc")
    for length in range(2, len(password) // 2 + 1):
        for i in range(len(password) - length * 2 + 1):
            chunk = password[i:i+length]
            if password[i+length:i+length*2] == chunk:
                return (True, 12, 
                        f"Repeated sequence '{chunk}': Repeated patterns are detected by "
                        f"rule-based attacks that specifically look for duplication. Each repeat "
                        f"makes the password exponentially weaker.")
    
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
                return (True, 15, 
                        f"Sequential pattern ({seq_len} chars): Long sequences like 'abcd' or "
                        f"'defg' appear in cracking dictionaries because they're common typing patterns. "
                        f"Break sequences with random characters.")
            else:
                return (True, 10, 
                        f"Sequential '{seq}': Three-character sequences are easily guessed. "
                        f"Attackers use 'sequence rules' that automatically generate abc, bcd, xyz, etc.")
    
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
                    return (True, 15, 
                            f"Numeric sequence ({seq_len} digits): Sequences like '1234' or '5678' "
                            f"are among the first patterns attackers try. Use random numbers instead.")
                else:
                    return (True, 10, 
                            f"Numeric sequence '{password[i:i+3]}': Consecutive numbers are "
                            f"predictable. Scatter random digits instead: '1', '9', '4'.")
    
    return False, 0, None

def detect_keyboard_walk(password):
    """
    Detects keyboard walk patterns
    Returns (has_walk, penalty, description)
    """
    pw_lower = password.lower()
    
    for pattern in KEYBOARD_PATTERNS:
        if pattern in pw_lower:
            return (True, 12, 
                    f"Keyboard walk '{pattern}': Typing adjacent keys ('qwerty', 'asdf') is "
                    f"a well-known pattern. Cracking tools include keyboard-walk generators that "
                    f"try all possible paths across the keyboard.")
        # Check reverse
        if pattern[::-1] in pw_lower:
            return (True, 12, 
                    f"Reverse keyboard walk '{pattern[::-1]}': Even reversed keyboard patterns "
                    f"are in attacker wordlists. Avoid using keyboard positions entirely.")
    
    return False, 0, None

def detect_date_patterns(password):
    """
    Detects common date-related patterns with realistic constraints.
    Returns (has_date, penalty, description)
    """
    date_patterns = [
        # Likely birth years (1950–2049)
        (r'(19[5-9]\d|20[0-4]\d)', 
         "Birth year detected: Years (especially 1960-2000) are extremely common in passwords. "
         "Attackers prioritize trying birth years, graduation years, and current years. "
         "Use unrelated numbers instead."),

        # Common date formats
        (r'\b\d{2}[/-]\d{2}[/-]\d{2,4}\b', 
         "Date format detected (DD/MM/YYYY): Formatted dates are easily recognized. "
         "Attackers use date-pattern generators that try birthdays, anniversaries, and historical dates."),

        # Compact YYYYMMDD
        (r'\b(19[5-9]\d|20[0-4]\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\b',
         "Compact date (YYYYMMDD): This format is checked by specialized date-cracking rules. "
         "Personal dates are easily researched via social media.")
    ]

    for pattern, description in date_patterns:
        if re.search(pattern, password):
            return True, 8, description

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
# Enhanced strength check with adaptive feedback
# -------------------------------
def check_strength(password):
    strength_points = 0
    feedback = []
    pattern_penalties = []

    # Character type checks
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    length = len(password)

    # Award points for complexity
    if length >= 8:
        strength_points += 1
    if has_lower:
        strength_points += 1
    if has_upper:
        strength_points += 1
    if has_digit:
        strength_points += 1
    if has_symbol:
        strength_points += 1

    # Get adaptive feedback
    adaptive_feedback = get_adaptive_feedback(
        password, has_lower, has_upper, has_digit, has_symbol, length
    )
    feedback.extend(adaptive_feedback)

    # Common password check
    if password.lower() in common_passwords:
        feedback.append(
            "❌ Extremely common password: This exact password appears in the top 100 most "
            "used passwords globally. It will be the first thing attackers try. Create something "
            "unique that isn't in any password list."
        )

    # Calculate base entropy
    entropy = calculate_entropy(password)

    # Pattern detection with enhanced descriptions
    total_pattern_penalty = 0
    
    # Check repetition
    has_rep, rep_penalty, rep_desc = detect_repetition(password)
    if has_rep:
        feedback.append(f"⚠️ {rep_desc}")
        pattern_penalties.append(("Repetition", rep_penalty))
        total_pattern_penalty += rep_penalty
    
    # Check sequences
    has_seq, seq_penalty, seq_desc = detect_sequences(password)
    if has_seq:
        feedback.append(f"⚠️ {seq_desc}")
        pattern_penalties.append(("Sequence", seq_penalty))
        total_pattern_penalty += seq_penalty
    
    # Check keyboard walks
    has_walk, walk_penalty, walk_desc = detect_keyboard_walk(password)
    if has_walk:
        feedback.append(f"⚠️ {walk_desc}")
        pattern_penalties.append(("Keyboard walk", walk_penalty))
        total_pattern_penalty += walk_penalty
    
    # Check date patterns
    has_date, date_penalty, date_desc = detect_date_patterns(password)
    if has_date:
        feedback.append(f"⚠️ {date_desc}")
        pattern_penalties.append(("Date pattern", date_penalty))
        total_pattern_penalty += date_penalty

    # Dictionary check with context
    pw_lower = password.lower()
    longest_match = ""
    for word in dictionary_words:
        if len(word) >= 4 and word in pw_lower:
            if len(word) > len(longest_match):
                longest_match = word

    # Dictionary penalties with explanations
    if pw_lower in dictionary_words:
        feedback.append(
            f"❌ Extremely common password: '{pw_lower}' appears in common dictionaries. "
            f"Attackers start with dictionary attacks before trying brute force. "
            f"Use a passphrase (3-4 random words) or add significant random elements."
        )
        entropy -= 20
    elif longest_match:
        if len(password) <= 6:
            feedback.append(
                f"❌ Contains dictionary word '{longest_match}': Short passwords based on words "
                f"are cracked quickly via 'hybrid attacks' that combine dictionary words with "
                f"common number/symbol patterns. Use a longer passphrase or completely random password."
            )
            entropy -= 20
        elif len(password) <= 10:
            feedback.append(
                f"⚠️ Contains dictionary word '{longest_match}': Dictionary words reduce entropy "
                f"because attackers use 'combination attacks' that mix common words with variations. "
                f"Consider using multiple unrelated words or more random characters."
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

    # Add positive feedback for strong passwords
    if not feedback or (rating in ["Strong", "Very Strong"] and entropy >= 70):
        feedback.append(
            "✅ Excellent password strength! This password uses good entropy and "
            "avoids common patterns. Continue using unique passwords for each account."
        )

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

    print("\n🔍 Breach Check:")
    print(f"  {check_breach(password)}")