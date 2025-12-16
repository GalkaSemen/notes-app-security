from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from models import User  # Импортируем модель для валидации

class NoteForm(FlaskForm):
    """
    Форма для создания и редактирования заметок.
    Наследование от FlaskForm обеспечивает автоматическую генерацию
    и валидацию CSRF токенов для всех экземпляров формы.
    """
    title = StringField('Заголовок', validators=[
        DataRequired(message='Заголовок обязателен'),
        Length(max=100, message='Заголовок не более 100 символов')
    ])
    content = TextAreaField('Содержание', validators=[
        DataRequired(message='Содержание обязательно')
    ])
    submit = SubmitField('Сохранить')


class LoginForm(FlaskForm):
    """Форма для входа пользователя (уязвимая версия для демонстрации SQL-инъекций)"""
    username = StringField('Имя пользователя', validators=[
        DataRequired(message='Имя пользователя обязательно')
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(message='Пароль обязателен')
    ])
    submit = SubmitField('Войти')


class RegisterForm(FlaskForm):
    """Форма для регистрации нового пользователя"""
    username = StringField('Имя пользователя', validators=[
        DataRequired(message='Имя пользователя обязательно'),
        Length(min=3, max=80, message='Имя пользователя от 3 до 80 символов')
    ])
    password = PasswordField('Пароль', validators=[
        DataRequired(message='Пароль обязателен'),
        Length(min=6, message='Пароль должен быть не менее 6 символов')
    ])
    confirm_password = PasswordField('Подтвердите пароль', validators=[
        DataRequired(message='Подтверждение пароля обязательно'),
        EqualTo('password', message='Пароли должны совпадать')
    ])
    submit = SubmitField('Зарегистрироваться')
    
    def validate_username(self, username):
        """Кастомная валидация: проверка уникальности имени пользователя"""
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Это имя пользователя уже занято')