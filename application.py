from flask import Flask
app = Flask(__name__, static_url_path='')

@app.route("/")
def hello():
    return url_for('static', filename='index.html')