FROM python:3.9-slim

WORKDIR /app

COPY app.py .
COPY requirements.txt .

RUN pip install -r requirements.txt

RUN apt-get update && apt-get install -y cron curl wget

RUN echo '#!/bin/bash\necho "Vulnerable cron job executed"' > /tmp/vuln_script.sh
RUN chmod +x /tmp/vuln_script.sh

RUN echo "SECRET_TOKEN=super_secret_token_12345" > /app/secrets.txt

EXPOSE 8000

CMD ["python", "app.py"]
