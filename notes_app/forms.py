from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length

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