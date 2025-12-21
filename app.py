# app.py - Updated version
from flask import Flask, render_template, request
from password_str import check_strength, check_breach

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        password = request.form["password"]
        rating, entropy, feedback, crack_time, crack_time_fast, pattern_penalties = check_strength(password)
        result = {
            "rating": rating,
            "entropy": entropy,
            "feedback": feedback,
            "breach": check_breach(password),
            "crack_time": crack_time,
            "crack_time_fast": crack_time_fast,
            "pattern_penalties": pattern_penalties
        }
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)