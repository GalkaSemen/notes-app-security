from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    session_id = db.Column(db.String(100), nullable=False)  # Для имитации контроля доступа
    # Добавляем внешний ключ для связи с User
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Пока nullable=True для обратной совместимости
    
    def __repr__(self):
        return f'<Note {self.title}>'


class User(db.Model):
    """Модель пользователя для аутентификации"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Упрощаем связь - убираем foreign_keys, так как нет реального внешнего ключа в Note
    notes = db.relationship('Note', backref='author', lazy=True)
    
    def set_password(self, password):
        """Установка хэшированного пароля"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Проверка пароля"""
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'