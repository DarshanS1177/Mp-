

from __future__ import annotations

import sqlite3
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from flask import Flask, render_template, request
from sklearn.ensemble import RandomForestClassifier

import url_features

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing.pkl"
DATASET_PATH = BASE_DIR / "phishcoop.csv"
DB_PATH = BASE_DIR / "user_database.sqlite3"


def _init_user_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_register (
                user TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _load_model():
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)

    if not DATASET_PATH.exists():
        raise FileNotFoundError("No training dataset found for phishing model.")

    df = pd.read_csv(DATASET_PATH)
    features = df.drop(columns=["id", "Result"], errors="ignore")
    labels = df["Result"]
    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        max_depth=15,
        min_samples_split=2,
    )
    model.fit(features, labels)
    joblib.dump(model, MODEL_PATH)
    return model


app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
_init_user_db()
model = _load_model()


@app.route('/')
def home():
    return render_template('register.html')


@app.route('/register', methods=['POST'])
def register():
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''

    if not username or not password:
        return render_template('register.html', text='Please enter both username and password.')

    with sqlite3.connect(DB_PATH) as conn:
        existing = conn.execute(
            'SELECT 1 FROM user_register WHERE user = ?', (username,)
        ).fetchone()
        if existing:
            return render_template('register.html', text='This Username is Already in Use')

        conn.execute(
            'INSERT INTO user_register(user, password) VALUES (?, ?)',
            (username, password),
        )
        conn.commit()

    return render_template('register.html', text='Succesfully Registered')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/logedin', methods=['POST'])
def logedin():
    username = (request.form.get('username') or '').strip()
    password = request.form.get('password') or ''

    with sqlite3.connect(DB_PATH) as conn:
        record = conn.execute(
            'SELECT password FROM user_register WHERE user = ?', (username,)
        ).fetchone()

    if record and record[0] == password:
        return render_template('index1.html')

    return render_template('login.html', text='Use Proper Username and Password')


@app.route('/production')
def production():
    return render_template('index1.html')


@app.route('/production/predict', methods=['POST'])
def predict():
    target_url = (request.form.get('url') or request.form.get('website') or '').strip()
    if not target_url:
        return render_template('index1.html', prediction_text='Please enter a URL to analyze.')

    url_processed = pd.DataFrame(
        [url_features.main(target_url)],
        columns=url_features.FEATURE_COLUMNS,
        dtype=float,
    )
    prediction = model.predict(url_processed)[0]

    if int(prediction) == -1:
        return render_template('index1.html', prediction_text='This is a Phishing Website')
    return render_template('index1.html', prediction_text='This is not a Phishing Website')


if __name__ == '__main__':
    app.run(debug=False)
