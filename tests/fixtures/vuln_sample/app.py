from flask import Flask, request, render_template_string
import os
import subprocess
import hashlib

app = Flask(__name__)

@app.route('/search')
def search():
    term = request.args.get('q', '')
    query = "SELECT * FROM users WHERE name = '" + term + "'"
    return query

@app.route('/echo')
def echo():
    user_input = request.args.get('text', '')
    return render_template_string('<h1>' + user_input + '</h1>')

API_KEY = 'sk-test-secret'
PASSWORD_HASH = hashlib.md5(b'password').hexdigest()

@app.route('/run')
def run_cmd():
    cmd = request.args.get('cmd', '')
    subprocess.run(cmd, shell=True)
    return 'ok'

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

app.config["SESSION_COOKIE_SECURE"] = False

@app.errorhandler(Exception)
def handle_error(e):
    return str(e)

def find_orders(req):
    collection = _mongo_orders_collection()  # placeholder: fixture never runs, only scanned
    return collection.find(req.body)


def _mongo_orders_collection():
    """Stub so this fixture file is self-contained; never actually called."""
    raise NotImplementedError("fixture only -- not meant to be executed")