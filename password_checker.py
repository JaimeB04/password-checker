import hashlib
import requests
import re

def check_password_strength(password):
    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short (minimum 8 characters).")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")
    
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")
    
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add digits.")

    if re.search(r"[@$!%*?&#]", password):
        score += 1
    else:
        feedback.append("Add special characters (@, $, !, %, etc.).")
    
    if score >= 4:
        strength = "Strong"
    elif score == 3:
        strength = "Medium"
    else:
        strength = "Weak"
    
    return strength, feedback

def check_pwned_api(password):
    sha1_pw = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5, tail = sha1_pw[:5], sha1_pw[5:]

    response = requests.get(f"https://api.pwnedpasswords.com/range/{first5}")
    if response.status_code != 200:
        raise RuntimeError("API request failed.")
    
    hashes = (line.split(":") for line in response.text.splitlines())
    for h, count in hashes:
        if h == tail:
            return int(count)
    return 0

def main():
    print("===== PASSWORD STRENGTH & BREACH CHECKER =====\n")
    password = input("Enter a password to test: ")

    strength, feedback = check_password_strength(password)
    print(f"\nPassword Strength: {strength}")
    if feedback:
        for f in feedback:
            print(f" {f}")

    print("\nChecking against known breaches (Have I Been Pwned)...")
    count = check_pwned_api(password)
    if count:
        print(f"This password has appeared in {count} known breaches! Change it immediately.")
    else:
        print("This password has Not appeared in know breaches.")

if __name__ == "__main__":
    main()