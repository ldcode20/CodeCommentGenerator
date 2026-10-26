"""Cross-site scripting (SEC014) / template injection (SEC015) — secure cases."""
import html

from flask import Flask, Response, jsonify, make_response, render_template, render_template_string, request
from markupsafe import escape

app = Flask(__name__)
COLORS = ("red", "green", "blue")


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template("hello.html", name=name)  # safe: SEC014


@app.route("/search")
def search():
    q = request.args["q"]
    return make_response("<p>Results for " + escape(q) + "</p>")  # safe: SEC014


@app.route("/html-escape")
def html_escape():
    q = request.args["q"]
    return f"<p>{html.escape(q)}</p>"  # safe: SEC014


@app.route("/api")
def api():
    q = request.args["q"]
    return jsonify({"query": q})  # safe: SEC014


@app.route("/raw-json")
def raw_json():
    q = request.args["q"]
    return Response('{"q": "' + q + '"}', mimetype="application/json")  # safe: SEC014


@app.route("/color")
def color():
    c = request.args["c"]
    if c not in COLORS:
        return "unknown"
    return "<span class='" + c + "'>ok</span>"  # safe: SEC014


@app.route("/count")
def count():
    return "<p>%d results</p>" % len(request.args["q"])  # safe: SEC014


@app.route("/greet")
def greet():
    name = request.args["name"]
    return render_template_string("Hello {{ name }}", name=name)  # safe: SEC015
