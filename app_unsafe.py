# ЭТОТ ФАЙЛ СОДЕРЖИТ УЯЗВИМОСТИ ДЛЯ ДЕМОНСТРАЦИИ
# Pipeline должен заблокировать merge этого кода

from flask import Flask

app = Flask(__name__)

# ⚠️ УЯЗВИМОСТЬ 1: Debug mode в production
app.debug = True  # Это вызовет падение pipeline!

# ⚠️ УЯЗВИМОСТЬ 2: Секретный ключ в коде
app.config['SECRET_KEY'] = 'this-is-very-secret-key'

# ⚠️ УЯЗВИМОСТЬ 3: SQL-инъекция (пример)
def unsafe_query(user_input):
    import sqlite3
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    
    # ⚠️ ОПАСНО: конкатенация строк
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)  # Bandit обнаружит эту уязвимость
    
    return cursor.fetchall()

if __name__ == '__main__':
    # ⚠️ УЯЗВИМОСТЬ 4: Запуск с debug
    app.run(debug=False, host='0.0.0.0', port=5000)
    print("❌ Этот код не должен пройти проверки безопасности!")
