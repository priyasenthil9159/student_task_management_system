import os
import re
import sqlite3
from datetime import date, datetime
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "database.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
VALID_STATUSES = ("Pending", "Completed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    email    TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    task_title  TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'Pending'
                CHECK (status IN ('Pending', 'Completed')),
    due_date    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
"""


def get_db():
    """Open one database connection per request and reuse it."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row          # access columns by name
        g.db.execute("PRAGMA foreign_keys = ON")  # enforce the foreign key
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(SCHEMA)
    db.commit()
    db.close()
def login_required(view):
    """Redirect to login if there is no user in the session."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def get_user_task_or_404(task_id):
    """
    Fetch a task ONLY if it belongs to the logged-in user.
    Changing the ID in the URL to someone else's task gives a 404.
    """
    task = get_db().execute(
        "SELECT * FROM tasks WHERE id = ? AND user_id = ?",
        (task_id, session["user_id"]),
    ).fetchone()
    if task is None:
        abort(404)
    return task

def validate_registration(name, email, password, confirm):
    errors = []
    if not name or not email or not password or not confirm:
        errors.append("All fields are required.")
        return errors
    if len(name) < 2 or len(name) > 50:
        errors.append("Name must be between 2 and 50 characters.")
    if not EMAIL_REGEX.match(email):
        errors.append("Please enter a valid email address.")
    if len(password) < 6:
        errors.append("Password must be at least 6 characters long.")
    elif not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        errors.append("Password must contain at least one letter and one number.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


def validate_task(title, description, status, due_date):
    errors = []
    if not title:
        errors.append("Task title is required.")
    elif len(title) < 3 or len(title) > 100:
        errors.append("Task title must be between 3 and 100 characters.")
    if len(description) > 500:
        errors.append("Description cannot be longer than 500 characters.")
    if status not in VALID_STATUSES:
        errors.append("Status must be either Pending or Completed.")
    if not due_date:
        errors.append("Due date is required.")
    else:
        try:
            datetime.strptime(due_date, "%Y-%m-%d")
        except ValueError:
            errors.append("Due date must be a valid date (YYYY-MM-DD).")
    return errors


def read_task_form():
    """Read and clean the task form fields."""
    return {
        "task_title": request.form.get("task_title", "").strip(),
        "description": request.form.get("description", "").strip(),
        "status": request.form.get("status", "Pending").strip(),
        "due_date": request.form.get("due_date", "").strip(),
    }


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    form = {"name": "", "email": ""}
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        form = {"name": name, "email": email}

        errors = validate_registration(name, email, password, confirm)

        if not errors:
            db = get_db()
            exists = db.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()
            if exists:
                errors.append("An account with this email already exists.")

        if errors:
            for e in errors:
                flash(e, "danger")
        else:
            db.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, generate_password_hash(password)),
            )
            db.commit()
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    email = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "danger")
        else:
            user = get_db().execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
            if user and check_password_hash(user["password"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["user_name"] = user["name"]
                flash(f"Welcome back, {user['name']}!", "success")
                return redirect(url_for("dashboard"))
            # Same message for wrong email or wrong password (safer)
            flash("Invalid email or password.", "danger")

    return render_template("login.html", email=email)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = session["user_id"]
    today = date.today().isoformat()

    # Summary counts for the four dashboard cards
    stats = db.execute(
        """SELECT COUNT(*) AS total,
                  COALESCE(SUM(status = 'Pending'), 0) AS pending,
                  COALESCE(SUM(status = 'Completed'), 0) AS completed,
                  COALESCE(SUM(status = 'Pending' AND due_date < ?), 0) AS overdue
           FROM tasks WHERE user_id = ?""",
        (today, uid),
    ).fetchone()

    # Optional filter: ?filter=pending|completed|overdue
    current_filter = request.args.get("filter", "all")
    sql = "SELECT * FROM tasks WHERE user_id = ?"
    params = [uid]
    if current_filter == "pending":
        sql += " AND status = 'Pending'"
    elif current_filter == "completed":
        sql += " AND status = 'Completed'"
    elif current_filter == "overdue":
        sql += " AND status = 'Pending' AND due_date < ?"
        params.append(today)
    else:
        current_filter = "all"
    sql += " ORDER BY due_date ASC, id DESC"

    tasks = db.execute(sql, params).fetchall()
    return render_template("dashboard.html", tasks=tasks, stats=stats,
                           today=today, current_filter=current_filter)


@app.route("/tasks/add", methods=["GET", "POST"])
@login_required
def add_task():
    form = {"task_title": "", "description": "", "status": "Pending", "due_date": ""}
    if request.method == "POST":
        form = read_task_form()
        errors = validate_task(form["task_title"], form["description"],
                               form["status"], form["due_date"])
        if errors:
            for e in errors:
                flash(e, "danger")
        else:
            db = get_db()
            db.execute(
                """INSERT INTO tasks
                   (user_id, task_title, description, status, due_date, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (session["user_id"], form["task_title"], form["description"],
                 form["status"], form["due_date"],
                 datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
            db.commit()
            flash("Task added successfully.", "success")
            return redirect(url_for("dashboard"))
    return render_template("add_task.html", form=form)


@app.route("/tasks/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
def edit_task(task_id):
    task = get_user_task_or_404(task_id)
    form = dict(task)
    if request.method == "POST":
        form = read_task_form()
        errors = validate_task(form["task_title"], form["description"],
                               form["status"], form["due_date"])
        if errors:
            for e in errors:
                flash(e, "danger")
        else:
            db = get_db()
            db.execute(
                """UPDATE tasks
                   SET task_title = ?, description = ?, status = ?, due_date = ?
                   WHERE id = ? AND user_id = ?""",
                (form["task_title"], form["description"], form["status"],
                 form["due_date"], task_id, session["user_id"]),
            )
            db.commit()
            flash("Task updated successfully.", "success")
            return redirect(url_for("dashboard"))
    return render_template("edit_task.html", form=form, task_id=task_id)


@app.route("/tasks/<int:task_id>/delete", methods=["POST"])
@login_required
def delete_task(task_id):
    get_user_task_or_404(task_id)  # makes sure the task belongs to this user
    db = get_db()
    db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?",
               (task_id, session["user_id"]))
    db.commit()
    flash("Task deleted.", "info")
    return redirect(url_for("dashboard"))


@app.route("/tasks/<int:task_id>/status", methods=["POST"])
@login_required
def update_status(task_id):
    get_user_task_or_404(task_id)
    new_status = request.form.get("status", "").strip()
    if new_status not in VALID_STATUSES:
        flash("Invalid status value.", "danger")
        return redirect(url_for("dashboard"))
    db = get_db()
    db.execute("UPDATE tasks SET status = ? WHERE id = ? AND user_id = ?",
               (new_status, task_id, session["user_id"]))
    db.commit()
    flash(f"Task marked as {new_status}.", "success")
    return redirect(url_for("dashboard"))

@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(error):
    return render_template("500.html"), 500


@app.errorhandler(sqlite3.Error)
def database_error(error):
    app.logger.error("Database error: %s", error)
    return render_template("500.html"), 500

STYLE_CSS = """
body { background-color: #f4f6f9; min-height: 100vh; display: flex; flex-direction: column; }
main { flex: 1; }
.navbar-brand { font-weight: 600; }
.auth-card { max-width: 460px; margin: 3rem auto; }
.stat-card { border: none; border-left: 5px solid #0d6efd; transition: transform .15s; }
.stat-card:hover { transform: translateY(-2px); }
.stat-card.pending { border-left-color: #ffc107; }
.stat-card.completed { border-left-color: #198754; }
.stat-card.overdue { border-left-color: #dc3545; }
.stat-number { font-size: 2rem; font-weight: 700; }
.task-desc { max-width: 280px; white-space: pre-wrap; word-wrap: break-word; }
.row-completed .task-title { text-decoration: line-through; color: #6c757d; }
footer { font-size: .85rem; }
"""

TEMPLATES = {
"base.html": """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Student Task Manager{% endblock %}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>{{ style_css|safe }}</style>
</head>
<body>
  <nav class="navbar navbar-expand-md navbar-dark bg-primary">
    <div class="container">
      <a class="navbar-brand" href="{{ url_for('home') }}">&#128218; Student Task Manager</a>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="nav">
        <ul class="navbar-nav ms-auto align-items-md-center">
          {% if session.get('user_id') %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('add_task') }}">Add Task</a></li>
            <li class="nav-item"><span class="navbar-text mx-md-3">Hi, {{ session.get('user_name') }}</span></li>
            <li class="nav-item"><a class="btn btn-outline-light btn-sm" href="{{ url_for('logout') }}">Logout</a></li>
          {% else %}
            <li class="nav-item"><a class="nav-link" href="{{ url_for('login') }}">Login</a></li>
            <li class="nav-item"><a class="nav-link" href="{{ url_for('register') }}">Register</a></li>
          {% endif %}
        </ul>
      </div>
    </div>
  </nav>

  <main class="container py-4">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
          {{ message }}
          <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      {% endfor %}
    {% endwith %}
    {% block content %}{% endblock %}
  </main>

  <footer class="text-center text-muted py-3">Student Task Management System &middot; Flask + SQLite + Bootstrap</footer>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>""",

"login.html": """{% extends 'base.html' %}
{% block title %}Login - Student Task Manager{% endblock %}
{% block content %}
<div class="card shadow-sm auth-card">
  <div class="card-body p-4">
    <h3 class="text-center mb-1">Welcome Back</h3>
    <p class="text-center text-muted mb-4">Log in to manage your tasks</p>
    <form method="POST" action="{{ url_for('login') }}" novalidate>
      <div class="mb-3">
        <label for="email" class="form-label">Email</label>
        <input type="email" class="form-control" id="email" name="email" value="{{ email }}" required>
      </div>
      <div class="mb-3">
        <label for="password" class="form-label">Password</label>
        <input type="password" class="form-control" id="password" name="password" required>
      </div>
      <button type="submit" class="btn btn-primary w-100">Login</button>
    </form>
    <p class="text-center mt-3 mb-0">New here? <a href="{{ url_for('register') }}">Create an account</a></p>
  </div>
</div>
{% endblock %}""",

"register.html": """{% extends 'base.html' %}
{% block title %}Register - Student Task Manager{% endblock %}
{% block content %}
<div class="card shadow-sm auth-card">
  <div class="card-body p-4">
    <h3 class="text-center mb-1">Create Account</h3>
    <p class="text-center text-muted mb-4">Register to start tracking your tasks</p>
    <form method="POST" action="{{ url_for('register') }}" novalidate>
      <div class="mb-3">
        <label for="name" class="form-label">Full Name</label>
        <input type="text" class="form-control" id="name" name="name" value="{{ form.name }}" required>
      </div>
      <div class="mb-3">
        <label for="email" class="form-label">Email</label>
        <input type="email" class="form-control" id="email" name="email" value="{{ form.email }}" required>
      </div>
      <div class="mb-3">
        <label for="password" class="form-label">Password</label>
        <input type="password" class="form-control" id="password" name="password" required>
        <div class="form-text">At least 6 characters, with a letter and a number.</div>
      </div>
      <div class="mb-3">
        <label for="confirm_password" class="form-label">Confirm Password</label>
        <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
      </div>
      <button type="submit" class="btn btn-primary w-100">Register</button>
    </form>
    <p class="text-center mt-3 mb-0">Already registered? <a href="{{ url_for('login') }}">Log in</a></p>
  </div>
</div>
{% endblock %}""",

"dashboard.html": """{% extends 'base.html' %}
{% block title %}Dashboard - Student Task Manager{% endblock %}
{% block content %}
<div class="d-flex justify-content-between align-items-center mb-3">
  <h2 class="mb-0">My Dashboard</h2>
  <a href="{{ url_for('add_task') }}" class="btn btn-primary">+ Add Task</a>
</div>

<div class="row g-3 mb-4">
  <div class="col-6 col-lg-3">
    <a href="{{ url_for('dashboard') }}" class="text-decoration-none text-dark">
      <div class="card stat-card shadow-sm"><div class="card-body">
        <div class="text-muted">Total Tasks</div><div class="stat-number">{{ stats.total }}</div>
      </div></div></a>
  </div>
  <div class="col-6 col-lg-3">
    <a href="{{ url_for('dashboard', filter='pending') }}" class="text-decoration-none text-dark">
      <div class="card stat-card pending shadow-sm"><div class="card-body">
        <div class="text-muted">Pending Tasks</div><div class="stat-number">{{ stats.pending }}</div>
      </div></div></a>
  </div>
  <div class="col-6 col-lg-3">
    <a href="{{ url_for('dashboard', filter='completed') }}" class="text-decoration-none text-dark">
      <div class="card stat-card completed shadow-sm"><div class="card-body">
        <div class="text-muted">Completed Tasks</div><div class="stat-number">{{ stats.completed }}</div>
      </div></div></a>
  </div>
  <div class="col-6 col-lg-3">
    <a href="{{ url_for('dashboard', filter='overdue') }}" class="text-decoration-none text-dark">
      <div class="card stat-card overdue shadow-sm"><div class="card-body">
        <div class="text-muted">Overdue Tasks</div><div class="stat-number">{{ stats.overdue }}</div>
      </div></div></a>
  </div>
</div>

<div class="card shadow-sm">
  <div class="card-header bg-white">
    <ul class="nav nav-pills">
      {% for key, label in [('all','All'),('pending','Pending'),('completed','Completed'),('overdue','Overdue')] %}
      <li class="nav-item">
        <a class="nav-link {{ 'active' if current_filter == key }}" href="{{ url_for('dashboard', filter=key) }}">{{ label }}</a>
      </li>
      {% endfor %}
    </ul>
  </div>
  <div class="card-body p-0">
    {% if tasks %}
    <div class="table-responsive">
      <table class="table table-hover align-middle mb-0">
        <thead class="table-light">
          <tr>
            <th>Title</th><th>Description</th><th>Status</th>
            <th>Due Date</th><th>Created</th><th class="text-end">Actions</th>
          </tr>
        </thead>
        <tbody>
          {% for t in tasks %}
          {% set is_overdue = t.status == 'Pending' and t.due_date < today %}
          <tr class="{{ 'row-completed' if t.status == 'Completed' }}">
            <td class="task-title fw-semibold">{{ t.task_title }}</td>
            <td class="task-desc">{{ t.description or '-' }}</td>
            <td>
              {% if t.status == 'Completed' %}
                <span class="badge bg-success">Completed</span>
              {% elif is_overdue %}
                <span class="badge bg-danger">Overdue</span>
              {% else %}
                <span class="badge bg-warning text-dark">Pending</span>
              {% endif %}
            </td>
            <td class="{{ 'text-danger fw-semibold' if is_overdue }}">{{ t.due_date }}</td>
            <td>{{ t.created_at[:10] }}</td>
            <td class="text-end text-nowrap">
              <form method="POST" action="{{ url_for('update_status', task_id=t.id) }}" class="d-inline">
                {% if t.status == 'Pending' %}
                  <input type="hidden" name="status" value="Completed">
                  <button class="btn btn-sm btn-outline-success">Mark Completed</button>
                {% else %}
                  <input type="hidden" name="status" value="Pending">
                  <button class="btn btn-sm btn-outline-secondary">Mark Pending</button>
                {% endif %}
              </form>
              <a href="{{ url_for('edit_task', task_id=t.id) }}" class="btn btn-sm btn-outline-primary">Edit</a>
              <form method="POST" action="{{ url_for('delete_task', task_id=t.id) }}" class="d-inline"
                    onsubmit="return confirm('Delete this task permanently?');">
                <button class="btn btn-sm btn-outline-danger">Delete</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}
    <div class="text-center text-muted py-5">
      <p class="mb-2">No tasks to show here yet.</p>
      <a href="{{ url_for('add_task') }}" class="btn btn-primary btn-sm">Add your first task</a>
    </div>
    {% endif %}
  </div>
</div>
{% endblock %}""",

"_task_form.html": """<form method="POST" action="{{ action }}" novalidate>
  <div class="mb-3">
    <label for="task_title" class="form-label">Task Title *</label>
    <input type="text" class="form-control" id="task_title" name="task_title"
           value="{{ form.task_title }}" maxlength="100" required>
  </div>
  <div class="mb-3">
    <label for="description" class="form-label">Description</label>
    <textarea class="form-control" id="description" name="description" rows="4" maxlength="500">{{ form.description }}</textarea>
  </div>
  <div class="row">
    <div class="col-md-6 mb-3">
      <label for="due_date" class="form-label">Due Date *</label>
      <input type="date" class="form-control" id="due_date" name="due_date" value="{{ form.due_date }}" required>
    </div>
    <div class="col-md-6 mb-3">
      <label for="status" class="form-label">Status *</label>
      <select class="form-select" id="status" name="status">
        <option value="Pending" {{ 'selected' if form.status == 'Pending' }}>Pending</option>
        <option value="Completed" {{ 'selected' if form.status == 'Completed' }}>Completed</option>
      </select>
    </div>
  </div>
  <div class="d-flex gap-2">
    <button type="submit" class="btn btn-primary">{{ submit_label }}</button>
    <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">Cancel</a>
  </div>
</form>""",

"add_task.html": """{% extends 'base.html' %}
{% block title %}Add Task - Student Task Manager{% endblock %}
{% block content %}
<div class="row justify-content-center"><div class="col-lg-7">
  <div class="card shadow-sm"><div class="card-body p-4">
    <h3 class="mb-4">Add New Task</h3>
    {% set action = url_for('add_task') %}
    {% set submit_label = 'Add Task' %}
    {% include '_task_form.html' %}
  </div></div>
</div></div>
{% endblock %}""",

"edit_task.html": """{% extends 'base.html' %}
{% block title %}Edit Task - Student Task Manager{% endblock %}
{% block content %}
<div class="row justify-content-center"><div class="col-lg-7">
  <div class="card shadow-sm"><div class="card-body p-4">
    <h3 class="mb-4">Edit Task</h3>
    {% set action = url_for('edit_task', task_id=task_id) %}
    {% set submit_label = 'Save Changes' %}
    {% include '_task_form.html' %}
  </div></div>
</div></div>
{% endblock %}""",

"404.html": """{% extends 'base.html' %}
{% block title %}Page Not Found{% endblock %}
{% block content %}
<div class="text-center py-5">
  <h1 class="display-1 fw-bold text-primary">404</h1>
  <h3>Page Not Found</h3>
  <p class="text-muted">The page or task you are looking for does not exist or is not yours.</p>
  <a href="{{ url_for('home') }}" class="btn btn-primary">Back to Home</a>
</div>
{% endblock %}""",

"500.html": """{% extends 'base.html' %}
{% block title %}Server Error{% endblock %}
{% block content %}
<div class="text-center py-5">
  <h1 class="display-1 fw-bold text-danger">500</h1>
  <h3>Something Went Wrong</h3>
  <p class="text-muted">An unexpected error occurred. Please try again.</p>
  <a href="{{ url_for('home') }}" class="btn btn-primary">Back to Home</a>
</div>
{% endblock %}""",
}

app.jinja_env.loader = DictLoader(TEMPLATES)
app.jinja_env.globals["style_css"] = STYLE_CSS

init_db()  # create tables if they do not exist yet

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
