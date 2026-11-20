from flask import Flask, request, render_template_string

app = Flask(__name__)

BASE_HTML = """
<!doctype html>
<html>
  <head><title>Local Scanner Lab</title></head>
  <body>
    <nav>
      <a href="/">Home</a> |
      <a href="/search?q=hello">Search</a> |
      <a href="/feedback">Feedback Form</a>
    </nav>
    <hr>
    {{ content | safe }}
  </body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(BASE_HTML, content="<h1>Welcome to Local Scanner Lab</h1><p>Test target for Phase 1 & 2.</p>")

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Intentionally unescaped output so you can test XSS detection locally
    body = f"<h2>Search Results for: {q}</h2>"
    return render_template_string(BASE_HTML, content=body)

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    message = ""
    if request.method == "POST":
        comment = request.form.get("comment", "")
        email = request.form.get("email", "")
        message = f"<p>Received from {email}: {comment}</p>"
    form_html = """
    <h2>Submit Feedback</h2>
    <form method="POST" action="/feedback">
      <input type="text" name="email" placeholder="Email">
      <textarea name="comment" placeholder="Comment"></textarea>
      <button type="submit">Send</button>
    </form>
    """ + message
    return render_template_string(BASE_HTML, content=form_html)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
