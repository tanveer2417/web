from flask import Flask
from flask_session import Session

app = Flask(__name__)
app.secret_key = 'supersecret'
app.config['SESSION_TYPE'] = 'filesystem'

Session(app)

from app import routes
