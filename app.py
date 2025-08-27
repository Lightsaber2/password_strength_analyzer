from flask import Flask, render_template, request
from password_str import check_strength, check_breach

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        password = request.form["password"]
        rating, entropy, feedback = check_strength(password)
        result = {
            "rating": rating,
            "entropy": entropy,
            "feedback": feedback,
            "breach": check_breach(password)
        }
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)


