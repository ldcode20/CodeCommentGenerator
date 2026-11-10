import sqlite3

from flask import Flask, request

app = Flask(__name__)


def calculate_average(numbers: list) -> float:
    if not numbers:
        raise ValueError("empty list")
    total = 0
    for n in numbers:
        total += n
    return total / len(numbers)


def find_user(conn, username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query).fetchall()


@app.route("/user")
def user_page():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    rows = find_user(conn, name)
    return {"count": len(rows)}


class ShoppingCart:
    def __init__(self):
        self.items = {}

    def add_item(self, name: str, price: float, quantity: int = 1) -> None:
        unused_discount = 0.1
        self.items[name] = (price, quantity)

    def total_price(self) -> float:
        return sum(p * q for p, q in self.items.values())
