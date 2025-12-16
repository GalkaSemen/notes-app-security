import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from models import db, Note, User
from forms import NoteForm, LoginForm, RegisterForm  # ← Добавили новые формы
from dotenv import load_dotenv
from security import setup_security  # ← Импорт middleware
import sqlite3  # Для демонстрации уязвимых SQL-запросов

# ====================== НАСТРОЙКА ЛОГИРОВАНИЯ FLASK ======================
# ДОБАВЛЕНО ДЛЯ ПР7 - Начало нового кода

import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import functools

def setup_flask_logging():
    """Настройка расширенного логирования Flask для ПР7"""
    
    # Создаем кастомный логгер
    logger = logging.getLogger('flask_app')
    logger.setLevel(logging.INFO)
    
    # Формат логов: время, IP, пользователь, сообщение
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [IP:%(ip)s] [USER:%(user)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Файловый обработчик с ротацией (10 MB, 5 файлов)
    file_handler = RotatingFileHandler(
        'flask_app.log',
        maxBytes=10485760,  # 10 MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Консольный обработчик для отладки
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

# Создаем глобальный логгер
flask_logger = setup_flask_logging()

# Декоратор для логирования запросов
def log_request(f):
    """Декоратор для логирования HTTP-запросов"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request, session
        
        user = session.get('username', 'anonymous')
        ip = request.remote_addr
        
        # Логируем ВСЕ запросы
        flask_logger.info(
            f"ENDPOINT: {request.path} | METHOD: {request.method} | USER_AGENT: {request.user_agent.string[:100]}",
            extra={'ip': ip, 'user': user}
        )
        
        # Детальное логирование для аутентификации
        if request.path in ['/login_secure', '/register_secure', '/login_vulnerable']:
            if request.method == 'POST':
                # Безопасно логируем данные (не логируем пароли полностью)
                safe_data = dict(request.form)
                if 'password' in safe_data:
                    safe_data['password'] = '***'  # Маскируем пароль
                
                flask_logger.warning(
                    f"AUTH_ATTEMPT: {request.path} | DATA: {safe_data}",
                    extra={'ip': ip, 'user': user}
                )
        
        # Детальное логирование для опасных операций
        if request.path.startswith('/delete/') or request.path.startswith('/update/'):
            flask_logger.warning(
                f"DANGEROUS_OPERATION: {request.path} | METHOD: {request.method}",
                extra={'ip': ip, 'user': user}
            )
        
        # Обработка исключений с логированием
        try:
            response = f(*args, **kwargs)
            return response
        except Exception as e:
            flask_logger.error(
                f"EXCEPTION in {request.path}: {str(e)}",
                extra={'ip': ip, 'user': user},
                exc_info=True  # Добавляет traceback
            )
            raise
    
    return decorated_function

# ====================== ИМПОРТЫ И НАСТРОЙКА FLASK ======================
# СУЩЕСТВУЮЩИЙ КОД (начало)


# Загружаем переменные окружения
load_dotenv()

# Создаем приложение Flask
app = Flask(__name__)

# Конфигурация приложения
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("SECRET_KEY не установлен в переменных окружения")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация базы данных
db.init_app(app)

# Подключение middleware безопасности (из security.py)
app = setup_security(app)

# Инициализация базы данных и создание тестового пользователя
with app.app_context():
    db.create_all()
    
    # Создаем тестового пользователя для демонстрации
    try:
        if not User.query.filter_by(username='testuser').first():
            test_user = User(username='testuser')
            test_user.set_password('password123')
            db.session.add(test_user)
            db.session.commit()
            print("✅ Создан тестовый пользователь: testuser / password123")
    except Exception as e:
        print(f"⚠️ Ошибка при создании тестового пользователя: {e}")

# ====================== CRUD ОПЕРАЦИИ С ЗАМЕТКАМИ ======================

@app.route('/')
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def index():
    """Главная страница со списком заметок"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    user_notes = Note.query.filter_by(session_id=session.get('session_id')).all()
    form = NoteForm()
    return render_template('index.html', notes=user_notes, form=form)

@app.route('/add', methods=['POST'])
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def add_note():
    """Добавление новой заметки"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    form = NoteForm()
    if form.validate_on_submit():
        if 'session_id' not in session:
            import secrets
            session['session_id'] = secrets.token_hex(16)
        
        new_note = Note(
            title=form.title.data,
            content=form.content.data,
            session_id=session['session_id']
        )
        db.session.add(new_note)
        db.session.commit()
        flash('Заметка успешно создана!', 'success')
        return redirect(url_for('index'))
    
    return redirect(url_for('index'))

@app.route('/edit/<int:note_id>')
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def edit_note(note_id):
    """Страница редактирования заметки"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    note = Note.query.get_or_404(note_id)
    if note.session_id != session.get('session_id'):
        flash('У вас нет прав для редактирования этой заметки', 'error')
        return redirect(url_for('index'))
    
    form = NoteForm()
    form.title.data = note.title
    form.content.data = note.content
    return render_template('edit.html', form=form, note=note)

@app.route('/update/<int:note_id>', methods=['POST'])
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def update_note(note_id):
    """Обновление существующей заметки"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    note = Note.query.get_or_404(note_id)
    if note.session_id != session.get('session_id'):
        flash('У вас нет прав для редактирования этой заметки', 'error')
        return redirect(url_for('index'))
    
    form = NoteForm()
    if form.validate_on_submit():
        note.title = form.title.data
        note.content = form.content.data
        db.session.commit()
        flash('Заметка успешно обновлена!', 'success')
        return redirect(url_for('index'))
    
    return redirect(url_for('edit_note', note_id=note_id))

@app.route('/delete/<int:note_id>')
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def delete_note(note_id):
    """Удаление заметки"""
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    note = Note.query.get_or_404(note_id)
    if note.session_id != session.get('session_id'):
        flash('У вас нет прав для удаления этой заметки', 'error')
        return redirect(url_for('index'))
    
    db.session.delete(note)
    db.session.commit()
    flash('Заметка успешно удалена!', 'success')
    return redirect(url_for('index'))

# ====================== АУТЕНТИФИКАЦИЯ И РЕГИСТРАЦИЯ ======================

@app.route('/login', methods=['GET'])
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def login_page():
    """Страница входа в систему"""
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET'])
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def register_page():
    """Страница регистрации нового пользователя"""
    form = RegisterForm()
    return render_template('register.html', form=form)

# ========== УЯЗВИМАЯ ВЕРСИЯ ВХОДА (для демонстрации SQL-инъекции) ==========

@app.route('/login_vulnerable', methods=['POST'])
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def login_vulnerable():
    """
    УЯЗВИМЫЙ метод входа с SQL-инъекцией.
    Используется для демонстрации атаки в ПР4.
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    if not username or not password:
        return "Ошибка: необходимо заполнить все поля", 400
    
    # ⚠️ ОПАСНО: прямое включение пользовательского ввода в SQL-запрос!
    query = f"SELECT * FROM user WHERE username = '{username}' AND password_hash = '{password}'"
    
    try:
        # Выполняем сырой SQL-запрос (УЯЗВИМОСТЬ!)
        connection = sqlite3.connect('instance/notes.db')
        cursor = connection.cursor()
        cursor.execute(query)
        user = cursor.fetchone()
        connection.close()
        
        if user:
            # Успешный вход (демонстрация уязвимости)
            return f"""
            <h1>УСПЕШНЫЙ ВХОД (УЯЗВИМЫЙ МЕТОД)!</h1>
            <p>Вы вошли как: <strong>{username}</strong></p>
            <p>Использованный запрос: <code>{query}</code></p>
            <p><a href="/">Перейти к заметкам</a> | <a href="/login">Выйти</a></p>
            <hr>
            <h3>Демонстрация SQL-инъекции:</h3>
            <p>Попробуйте ввести: <code>' OR '1'='1</code> в поле пароля</p>
            <p>Или: <code>' OR '1'='1' --</code> в поле имени пользователя</p>
            """
        else:
            return "Ошибка: неверное имя пользователя или пароль", 401
            
    except Exception as e:
        return f"Ошибка SQL: {str(e)}", 500

# ========== БЕЗОПАСНАЯ ВЕРСИЯ ВХОДА (исправленная) ==========

@app.route('/login_secure', methods=['POST'])
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def login_secure():
    """
    БЕЗОПАСНЫЙ метод входа с использованием ORM.
    Защищён от SQL-инъекций.
    """
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # ✅ БЕЗОПАСНО: поиск через SQLAlchemy ORM
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            # Успешный вход
            session['user_id'] = user.id
            session['username'] = user.username
            
            # Генерируем session_id для заметок
            if 'session_id' not in session:
                import secrets
                session['session_id'] = secrets.token_hex(16)
            
            flash(f'Добро пожаловать, {username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')
            return redirect(url_for('login_page'))
    
    return "Ошибка валидации формы", 400

@app.route('/register_secure', methods=['POST'])
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def register_secure():
    """Безопасная регистрация пользователя"""
    form = RegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Проверяем, не существует ли уже пользователь
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Пользователь с таким именем уже существует', 'error')
            return redirect(url_for('register_page'))
        
        # Создаём нового пользователя
        new_user = User(username=username)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Регистрация успешна! Теперь вы можете войти.', 'success')
        return redirect(url_for('login_page'))
    
    # Если валидация не прошла, показываем ошибки
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'Ошибка в поле {getattr(form, field).label.text}: {error}', 'error')
    
    return redirect(url_for('register_page'))

@app.route('/logout')
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def logout():
    """Выход из системы"""
    session.clear()
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('login_page'))

# ========== СТРАНИЦЫ ДЛЯ ДЕМОНСТРАЦИИ УЯЗВИМОСТЕЙ ==========

@app.route('/demo/vulnerable')
@log_request  # ← ДОБАВЛЕН ДЕКОРАТОР ДЛЯ ЛОГИРОВАНИЯ
def demo_vulnerable():
    """Страница демонстрации SQL-инъекции"""
    return '''
    <h1>Демонстрация SQL-инъекции</h1>
    <h3>Уязвимая форма входа:</h3>
    <form action="/login_vulnerable" method="POST">
        <input type="text" name="username" placeholder="Имя пользователя" required><br>
        <input type="password" name="password" placeholder="Пароль" required><br>
        <button type="submit">Войти (уязвимый метод)</button>
    </form>
    
    <hr>
    
    <h3>Примеры для тестирования:</h3>
    <ul>
        <li>Логин: <code>testuser</code>, Пароль: <code>password123</code> (правильные данные)</li>
        <li>Логин: <code>testuser</code>, Пароль: <code>' OR '1'='1</code> (SQL-инъекция)</li>
        <li>Логин: <code>' OR '1'='1' --</code>, Пароль: <code>любой</code> (SQL-инъекция)</li>
        <li>Логин: <code>admin' --</code>, Пароль: <code>любой</code> (комментирование запроса)</li>
    </ul>
    
    <p><a href="/login">Безопасный вход</a> | <a href="/">На главную</a></p>
    '''

# ====================== MIDDLEWARE ДЛЯ ЗАГОЛОВКОВ БЕЗОПАСНОСТИ ======================

@app.after_request
def add_security_headers(response):
    """Добавление HTTP-заголовков безопасности"""
    response.headers.pop('Server', None)
    response.headers['Server'] = 'SecureNotesServer/1.0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    
    # HSTS только для HTTPS (закомментировано для HTTP)
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# ====================== ЗАПУСК ПРИЛОЖЕНИЯ ======================

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    
    # Создаем файл лога при запуске
    if not os.path.exists('flask_app.log'):
        with open('flask_app.log', 'w') as f:
            f.write(f"=== Flask App Started at {datetime.now()} ===\n")
    
    app.run(
        debug=debug_mode,
        host='localhost',
        port=5001,
        # Дополнительные опции для лучшего логирования
        threaded=True,
        use_reloader=False  # Отключаем reloader для стабильного логирования
    )