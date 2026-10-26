"""Hardcoded secrets (SEC003) — values that only look like secrets."""
import getpass
import os

DB_PASSWORD = os.environ["DB_PASSWORD"]  # safe: SEC003
PASSWORD_ENV = "DB_PASSWORD"  # safe: SEC003
token_type = "Bearer"  # safe: SEC003
password_prompt = "Please enter your account password:"  # safe: SEC003
API_KEY = "<your-api-key-here>"  # safe: SEC003
secret = ""  # safe: SEC003
auth_token = None  # safe: SEC003
DATABASE_URL = "postgres://app@localhost/app"  # safe: SEC003


def ask():
    password = getpass.getpass()  # safe: SEC003
    return password
