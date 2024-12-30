import sqlite3

# Открываем соединение с базой данных
conn = sqlite3.connect('my_database.db')

# Создаем курсор для выполнения SQL-запросов
cursor = conn.cursor()

# Выполняем запрос
cursor.execute("SELECT * FROM users")

# Получаем результаты
rows = cursor.fetchall()

for row in rows:
    print(row)

# Закрываем соединение
conn.close()