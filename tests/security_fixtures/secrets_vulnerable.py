"""Hardcoded secrets (SEC003) — vulnerable cases."""
import psycopg2

DB_PASSWORD = "s3cr3t-Pa55w0rd!"  # expect: SEC003
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # expect: SEC003
DATABASE_URL = "postgres://admin:Sup3rS3cret@db.internal:5432/app"  # expect: SEC003

CONFIG = {
    "token": "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB",  # expect: SEC003
}


class ApiClient:
    def __init__(self):
        self.api_key = "a8f5f167f44f4964e6c998dee827110c"  # expect: SEC003


def connect():
    return psycopg2.connect(host="db", user="app", password="hunter2-prod")  # expect: SEC003


def check_login(password):
    return password == "letmein-2024"  # expect: SEC003


PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"  # expect: SEC003
