FROM python:3.15-rc-slim

# Установка cron
RUN apt-get update && apt-get install -y cron vim && rm -rf /var/lib/apt/lists/*

# Создание директории для приложения
WORKDIR /app

# Копирование скрипта
COPY cron.py /app/script.py
RUN chmod +x /app/script.py
RUN touch /app/test.sh

# Копирование crontab файла
COPY crontab /etc/cron.d/random-cron

# Установка прав на crontab файл
RUN chmod 0644 /etc/cron.d/random-cron

RUN mkdir -p /var/log
RUN touch /var/log/cron.log

# Применение crontab
RUN crontab /etc/cron.d/random-cron

# Запускаем cron и сразу смотрим логи
CMD ["sh", "-c", "cron && tail -f /var/log/cron.log"]
