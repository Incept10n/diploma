FROM python:3.15-rc-slim

RUN apt-get update && apt-get install -y cron vim && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY cron.py /app/script.py
RUN chmod +x /app/script.py
RUN touch /app/test.sh

COPY crontab /etc/cron.d/random-cron

RUN chmod 0644 /etc/cron.d/random-cron

RUN mkdir -p /var/log
RUN touch /var/log/cron.log

RUN crontab /etc/cron.d/random-cron

CMD ["sh", "-c", "cron && tail -f /var/log/cron.log"]
