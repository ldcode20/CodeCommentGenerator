"""Cross-site scripting (SEC014) and template injection (SEC015) — vulnerable cases."""
import shlex

from flask import Flask, Markup, make_response, render_template_string, request
from django.http import HttpResponse
from jinja2 import Template

app = Flask(__name__)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return f"<h1>Hello {name}</h1>"  # expect: SEC014


@app.route("/search")
def search():
    q = request.args["q"]
    return make_response("<p>Results for " + q + "</p>")  # expect: SEC014


@app.route("/bio")
def bio():
    text = request.form["bio"]
    return Markup(text)  # expect: SEC014


def django_echo(request):
    return HttpResponse("<b>" + request.GET["msg"] + "</b>")  # expect: SEC014


def render_box(message):
    return "<div class='box'>" + message + "</div>"


@app.route("/box")
def box():
    resp = make_response(render_box(request.args["m"]))  # expect: SEC014
    return resp


@app.route("/quoted")
def quoted():
    value = shlex.quote(request.args["v"])
    return make_response("<i>" + value + "</i>")  # expect: SEC014


@app.route("/greet")
def greet():
    tpl = request.args["template"]
    return render_template_string(tpl)  # expect: SEC015


def compile_user_template():
    src = request.form["tpl"]
    return Template(src).render()  # expect: SEC015
