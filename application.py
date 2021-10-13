import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    userId = session["user_id"]
    di = {}
    li = []
    userdata = db.execute("SELECT cash FROM users WHERE id = ?", userId)
    usercash = userdata[0]["cash"]
    totla_cash = 0.00
    rows = db.execute("SELECT * FROM new_history WHERE user_id = ? ", userId)
    for row in rows:
        result = lookup(row["symbol"])
        price = result["price"]
        name = result["name"]
        shares = row["shares"]
        total = float(shares) * price
        totla_cash = totla_cash + total
        di["symbol"] = row["symbol"]
        di["shares"] = row["shares"]
        di["name"] = name
        di["cost"] = price
        di["total"] = total
        li.append(di.copy())

    total_user_pay = float(usercash) + totla_cash
    return render_template("index.html", alldata=li, usercash=usercash, total_user_pay=total_user_pay, totla_cash=totla_cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        e = datetime.datetime.now()
        the_time = e.strftime("%Y-%m-%d %H:%M:%S")
        if not request.form.get("symbol"):
            return apology("you must type symbol", 400)
        symbol = request.form.get("symbol")
        result = lookup(symbol)
        if result == None:
            return apology("Not a valued symbol", 400)

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Shares must be more than (0)", 400)

        if shares <= 0:
            return apology("Shares must be more than (0)", 400)

        cost = result["price"]

        userId = session["user_id"]
        userCash = db.execute("SELECT cash FROM users WHERE id = ?", userId)
        ucash = userCash[0]["cash"]
        total = int(shares) * cost
        if ucash >= total:
            afterPurchase = ucash - total
            db.execute("UPDATE users SET cash = ? WHERE id= ?", afterPurchase, userId)
            db.execute("INSERT INTO new_history (user_id, symbol, cost, total, shares) VALUES ( ?, ?, ?, ?, ?)",
                       userId, symbol, cost, total, int(shares))
            db.execute("INSERT INTO real_history (user_id, symbol, cost, total, shares, the_time, the_type) VALUES ( ?, ?, ?, ?, ?, ?, ?)",
                       userId, symbol, cost, total, int(shares), the_time, "Buy")
            return redirect("/")
        else:
            return apology("You can't afford this many shares")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    alldata = db.execute("SELECT * FROM real_history WHERE user_id = ?", user_id)
    return render_template("history.html", alldata=alldata)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        result = lookup(symbol)
        if result == None:
            return apology("Not a valued symbol", 400)
        else:
            name = result["name"]
            price = result["price"]
            rSymbol = result["symbol"]
            return render_template("quoted.html", name=name, price=price, rSymbol=rSymbol)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)
        elif not request.form.get("confirmation"):
            return apology("must provide password", 400)

        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if password != confirmation:
            return apology("Password must be confirmed", 400)

        theUsername = request.form.get("username")
        hashPass = generate_password_hash(confirmation)

        username_check = db.execute("SELECT * FROM users WHERE username = ?", theUsername)
        if username_check != []:
            return apology("this username is taken", 400)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", theUsername, hashPass)
        return redirect("/")
    elif request.method == "GET":
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    user_data = db.execute("SELECT * FROM users WHERE id = ?", user_id)
    rows = db.execute("SELECT * FROM new_history WHERE user_id = ? ", user_id)
    symbols = db.execute("SELECT symbol FROM new_history WHERE user_id = ? ", user_id)
    if request.method == "POST":
        e = datetime.datetime.now()
        the_time = e.strftime("%Y-%m-%d %H:%M:%S")
        symbol = request.form.get("symbol")
        selected_shares = request.form.get("shares")

        if int(selected_shares) <= 0:
            return apology("You can't sell 0 or less than 0 shares", 403)
        result = lookup(symbol)
        user_symbol_data = db.execute("SELECT * FROM new_history WHERE user_id = ? AND symbol = ?", user_id, symbol)
        updated_shares = int(user_symbol_data[0]["shares"]) - int(selected_shares)
        if updated_shares == 0:
            updated_total = result["price"] * float(selected_shares)
            updated_cash = updated_total + user_data[0]["cash"]

            db.execute("DELETE FROM new_history WHERE user_id = ? AND symbol = ?", user_id, symbol)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, user_id)
        elif updated_shares > 0:
            updated_total = result["price"] * float(selected_shares)
            updated_cash = updated_total + user_data[0]["cash"]

            db.execute("UPDATE new_history SET shares = ? WHERE user_id = ? AND symbol = ?",
                       updated_shares, user_id, symbol)
            db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, user_id)

        else:
            return apology("You can't sell this many shares", 400)
        updated_total = result["price"] * float(selected_shares)
        db.execute("INSERT INTO real_history (user_id, symbol, cost, total, shares, the_time, the_type) VALUES ( ?, ?, ?, ?, ?, ?, ?)",
                   user_id, symbol, result["price"], updated_total, int(selected_shares), the_time, "Sell")

        return redirect("/")
        # return render_template("test.html", user_data=user_data[0], selected_shares=selected_shares)

    else:
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


@app.route("/changepass", methods=["GET", "POST"])
@login_required
def changepass():
    """Sell shares of stock"""
    if request.method == "POST":

        if not request.form.get("old_pass"):
            return apology("must input old password", 400)
        elif not request.form.get("new_pass"):
            return apology("must input new password", 400)
        elif not request.form.get("confirmation"):
            return apology("must input password confirmation", 400)

        user_id = session["user_id"]
        old_pass = request.form.get("old_pass")

        rows = db.execute("SELECT * FROM users WHERE id = ?", user_id)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], old_pass):
            return apology("invalid old password", 400)

        new_pass = request.form.get("new_pass")
        confirmation = request.form.get("confirmation")

        if new_pass != confirmation:
            return apology("invalid confirmation", 400)

        hashPass = generate_password_hash(confirmation)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hashPass, user_id)
        return redirect("/")
    else:
        return render_template("changepass.html")
