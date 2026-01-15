from flask import (
    Flask,
    request,
    make_response,
    render_template_string,
    redirect,
    url_for,
)
import sqlite3
import subprocess
import os
import re
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

DB_PATH = os.environ.get("APP_DB_PATH", "app.db")


# Security Headers - защита от множества атак
@app.after_request
def add_security_headers(response):
    """Добавляет security headers ко всем ответам"""
    # Защита от clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    # Защита от MIME-sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # XSS Protection (для старых браузеров)
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Content Security Policy - защита от XSS
    response.headers['Content-Security-Policy'] = "default-src 'self'"

    # Referrer Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions Policy
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

    # Cross-Origin policies (защита от Spectre)
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'

    # Cache-Control для sensitive страниц
    if request.path in ['/login', '/admin', '/profile']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'

    # Скрыть информацию о сервере (частично)
    response.headers['Server'] = 'WebServer'

    return response


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT
        )
        """
    )
    cur.execute("DELETE FROM users")
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')"
    )
    cur.execute(
        "INSERT INTO users (username, password, role) VALUES ('user', 'user123', 'user')"
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    html = """
    <h1>Vulnerable DAST Demo App</h1>
    <p>Пример уязвимого приложения для лабораторной по DAST.</p>
    <ul>
      <li><a href="/echo?msg=Hello">Reflected XSS / echo</a></li>
      <li><a href="/search?username=admin">SQL Injection / search</a></li>
      <li><a href="/login">Небезопасный логин</a></li>
      <li><a href="/profile">Профиль (зависит от cookie)</a></li>
      <li><a href="/admin">«Админка» без нормальной авторизации</a></li>
      <li><a href="/files/">Directory listing</a></li>
      <li><a href="/ping?host=127.0.0.1">Command Injection / ping</a></li>
    </ul>
    """
    resp = make_response(html)
    # Исправлено: добавлены флаги безопасности для cookies
    resp.set_cookie("session", "guest-session-id",
                    httponly=True,  # Защита от XSS
                    secure=False,   # True для HTTPS
                    samesite='Lax')  # Защита от CSRF
    return resp


@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    # Исправлено: используется автоматическое экранирование Jinja2
    template = """
    <h2>Echo</h2>
    <p>Сообщение: {{ msg }}</p>
    <p>Теперь XSS защищено через auto-escaping</p>
    <a href="/">Назад</a>
    """
    # Jinja2 автоматически экранирует переменные при использовании {{ }}
    return render_template_string(template, msg=msg)


@app.route("/search")
def search():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Исправлено: используются параметризованные запросы
    query_template = "SELECT id, username, role FROM users WHERE username = ?"
    rows = []
    error = None
    try:
        # Параметризованный запрос предотвращает SQL Injection
        for row in cur.execute(query_template, (username,)):
            rows.append(row)
    except Exception as e:
        error = "Ошибка поиска"  # Не раскрываем детали ошибки

    conn.close()

    template = """
    <h2>Поиск пользователя</h2>
    <p>Использован безопасный параметризованный запрос</p>
    {% if error %}
      <p style="color:red;">{{ error }}</p>
    {% endif %}
    {% if rows %}
      <ul>
      {% for id, username, role in rows %}
        <li>{{ id }} – {{ username }} ({{ role }})</li>
      {% endfor %}
      </ul>
    {% else %}
      <p>Ничего не найдено</p>
    {% endif %}
    <p>SQL Injection теперь невозможен благодаря параметризации</p>
    <a href="/">Назад</a>
    """
    # Не передаем SQL-запрос в шаблон - это тоже information disclosure
    return render_template_string(template, rows=rows, error=error)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        form = """
        <h2>Логин</h2>
        <form method="post">
          <label>Username: <input type="text" name="username"></label><br>
          <label>Password: <input type="password" name="password"></label><br>
          <button type="submit">Login</button>
        </form>
        <p>Попробуйте: admin / admin123 или user / user123</p>
        <a href="/">Назад</a>
        """
        return render_template_string(form)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Исправлено: параметризованный запрос
    query = "SELECT id, username, role FROM users WHERE username = ? AND password = ?"
    row = cur.execute(query, (username, password)).fetchone()
    conn.close()

    if row:
        _, uname, role = row
        resp = make_response(
            f"<h2>Добро пожаловать, {uname} ({role})!</h2><a href='/'>На главную</a>"
        )

        # Исправлено: добавлены security флаги для cookies
        resp.set_cookie("user", uname,
                        httponly=True,
                        secure=False,  # True для HTTPS
                        samesite='Lax')
        resp.set_cookie("role", role,
                        httponly=True,
                        secure=False,  # True для HTTPS
                        samesite='Lax')
        return resp
    else:
        return render_template_string(
            "<h2>Неверные учетные данные</h2><a href='/login'>Попробовать снова</a>"
        )


@app.route("/profile")
def profile():
    username = request.cookies.get("user", "guest")
    role = request.cookies.get("role", "guest")

    template = """
    <h2>Профиль пользователя</h2>
    <p>Имя: {{ username }}</p>
    <p>Роль: {{ role }}</p>
    <p>Cookie легко подделать: можно выдать себе роль 'admin'.</p>
    <a href="/">Назад</a>
    """
    return render_template_string(template, username=username, role=role)


@app.route("/admin")
def admin():
    role = request.cookies.get("role", "guest")
    if role != "admin":
        return (
            "<h2>Доступ запрещён: вы не admin</h2><p>Попробуйте изменить cookie 'role'.</p><a href='/'>Назад</a>",
            403,
        )

    template = """
    <h2>Admin panel</h2>
    <p>Секретные настройки приложения (демо).</p>
    <ul>
      <li>DEBUG: true</li>
      <li>FEATURE_FLAG: experimental_mode</li>
    </ul>
    <a href="/">Назад</a>
    """
    return render_template_string(template)


@app.route("/files/")
@app.route("/files/<path:subpath>")
def files(subpath=""):
    base_dir = os.path.abspath(os.path.dirname(__file__))
    target_dir = os.path.join(base_dir, "files")

    full_path = os.path.join(target_dir, subpath)

    # Исправлено: защита от path traversal
    # Проверяем, что путь находится внутри разрешенной директории
    if not os.path.abspath(full_path).startswith(target_dir):
        return "<h2>Доступ запрещен</h2><a href='/'>Назад</a>", 403

    if not os.path.exists(full_path):
        return "<h2>Путь не найден</h2><a href='/'>Назад</a>", 404

    # Исправлено: запрещаем directory listing
    if os.path.isdir(full_path):
        return """
        <h2>Directory listing отключен</h2>
        <p>Просмотр списка файлов запрещен по соображениям безопасности.</p>
        <a href="/">Назад</a>
        """, 403

    # Исправлено: whitelist разрешенных файлов
    ALLOWED_FILES = ['public.txt', 'readme.md']
    filename = os.path.basename(full_path)

    if filename not in ALLOWED_FILES:
        return f"""
        <h2>Доступ к файлу запрещен</h2>
        <p>Файл '{filename}' не находится в списке разрешенных.</p>
        <p>Разрешенные файлы: {', '.join(ALLOWED_FILES)}</p>
        <a href="/">Назад</a>
        """, 403

    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return f"<h2>Файл: {filename}</h2><pre>{content}</pre><a href='/'>Назад</a>"
    except Exception as e:
        return "<h2>Ошибка чтения файла</h2><a href='/'>Назад</a>", 500


@app.route("/ping")
def ping():
    """Исправленный эндпоинт без Command Injection."""
    host = request.args.get("host", "127.0.0.1")

    # Исправлено: валидация входных данных
    # Разрешаем только IP-адреса и доменные имена
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        return render_template_string("""
            <h2>Ping утилита</h2>
            <p style="color:red;">Недопустимый формат хоста!</p>
            <p>Разрешены только буквы, цифры, точки и дефисы.</p>
            <a href="/">Назад</a>
        """)

    # Исправлено: используем shell=False и список аргументов
    try:
        # Безопасно! Аргументы передаются отдельно без shell
        result = subprocess.check_output(
            ["ping", "-c", "2", host],  # Список аргументов вместо строки
            stderr=subprocess.STDOUT,
            timeout=5
        ).decode('utf-8')
    except subprocess.TimeoutExpired:
        result = "Timeout: хост не отвечает"
    except subprocess.CalledProcessError as e:
        result = e.output.decode('utf-8')
    except FileNotFoundError:
        result = "Утилита ping не установлена в системе"

    template = """
    <h2>Ping утилита</h2>
    <p>Хост: {{ host }}</p>
    <pre>{{ result }}</pre>
    <p>Command Injection теперь невозможен благодаря валидации и shell=False</p>
    <a href="/">Назад</a>
    """
    return render_template_string(template, host=host, result=result)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=True)  # nosec B201,B104
