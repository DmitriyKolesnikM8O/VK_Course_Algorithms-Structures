# Используем стабильный Python (3.14 пока слишком экспериментален для продакшена)
FROM python:3.12-slim

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    sudo \
    masscan \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Создаем рабочую директорию
WORKDIR /app

# Копируем зависимости и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь проект
COPY . .

# Открываем порт для веб-интерфейса
EXPOSE 5000

# Запускаем приложение
# Используем PYTHONPATH=., чтобы Python видел папку src
ENV PYTHONPATH=/app
CMD ["python", "app.py"]
