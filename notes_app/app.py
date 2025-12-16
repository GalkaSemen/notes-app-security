import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from models import db, Note
from forms import NoteForm # Импорт формы с встроенной CSRF защитой
from dotenv import load_dotenv
from security import setup_security  # ← Импорт middleware

load_dotenv()

app = Flask(__name__)

# Получаем SECRET_KEY из переменных окружения БЕЗ fallback значения
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("SECRET_KEY не установен в переменных окружения")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)


# Подключение middleware безопасности
app = setup_security(app)
# ======================

# Инициализация базы данных
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    # Получаем заметки только для текущей сессии (имитация контроля доступа)
    user_notes = Note.query.filter_by(session_id=session.get('session_id')).all()
    form = NoteForm()
    return render_template('index.html', notes=user_notes, form=form)

@app.route('/add', methods=['POST'])
def add_note():
    form = NoteForm()
    if form.validate_on_submit():
        # Генерируем session_id при первом обращении
        if 'session_id' not in session:
            import secrets
            session['session_id'] = secrets.token_hex(16)
        
        # Создаем новую заметку с привязкой к сессии
        new_note = Note(
            title=form.title.data,
            content=form.content.data,
            session_id=session['session_id']
        )
        db.session.add(new_note)
        db.session.commit()
        flash('Заметка успешно создана!', 'success')
        return redirect(url_for('index'))

@app.route('/edit/<int:note_id>')
def edit_note(note_id):
    # Проверка прав доступа (имитация защиты от IDOR)
    note = Note.query.get_or_404(note_id)
    # Проверяем, принадлежит ли заметка текущей сессии
    if note.session_id != session.get('session_id'):
        flash('У вас нет прав для редактирования этой заметки', 'error')
        return redirect(url_for('index'))
    
    form = NoteForm()
    form.title.data = note.title
    form.content.data = note.content
    return render_template('edit.html', form=form, note=note)

@app.route('/update/<int:note_id>', methods=['POST'])
def update_note(note_id):
    # Проверка прав доступа
    note = Note.query.get_or_404(note_id)
    if note.session_id != session.get('session_id'):
        flash('У вас нет прав для редактирования этой заметки', 'error')
        return redirect(url_for('index'))
    
    form = NoteForm()
    if form.validate_on_submit():
        # Обновляем заметку через ORM (безопасно от SQL-инъекций)
        note.title = form.title.data
        note.content = form.content.data
        db.session.commit()
        flash('Заметка успешно обновлена!', 'success')
        return redirect(url_for('index'))

@app.route('/delete/<int:note_id>')
def delete_note(note_id):
    # Проверка прав доступа
    note = Note.query.get_or_404(note_id)
    if note.session_id != session.get('session_id'):
        flash('У вас нет прав для удаления этой заметки', 'error')
        return redirect(url_for('index'))
    
    db.session.delete(note)
    db.session.commit()
    flash('Заметка успешно удалена!', 'success')
    return redirect(url_for('index'))



@app.after_request
def add_security_headers(response):
    """Добавление заголовков безопасности для ПР3"""
    # 1. Сначала УДАЛИТЬ существующий Server заголовок
    response.headers.pop('Server', None)
    
    # 2. Затем установить СВОЙ
    response.headers['Server'] = 'SecureNotesServer/1.0'
    
    # 3. Остальные заголовки
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'  # У вас уже DENY, это хорошо!
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'"

    # 4. HSTS - только для production с HTTPS
# В учебном проекте на HTTP HSTS не добавляем (браузеры игнорируют)
# В production с HTTPS раскомментировать:
# response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    
    return response

if __name__ == '__main__':
    # Режим отладки только для разработки
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(
        debug=debug_mode,
        host='localhost',
        port=5000
    )
    
