"""
    Flask web api module.
"""

from flask import Flask
from flask_cors import CORS
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from celery import Celery
from lisa.config import celery_broker, celery_backend, sql_backend

app = Flask(__name__)
app.url_map.strict_slashes = False
celery_app = Celery(app.name, backend=celery_backend, broker=celery_broker)
celery_app.conf.worker_hijack_root_logger = False
CORS(app)

engine = create_engine(sql_backend)
Session = sessionmaker(bind=engine)

from lisa.web_api import routes
