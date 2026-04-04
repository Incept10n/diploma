from flask import Flask, request, jsonify
import subprocess
import os
import time

app = Flask(__name__)

@app.route('/')
def index():
    return '<h1>Vulnerable Test Application</h1><p>This app is intentionally vulnerable for security testing</p>'

# Уязвимость RCE - не проверяем входные данные
@app.route('/exec')
def execute_command():
    cmd = request.args.get('cmd', '')
    if cmd:
        try:
            result = subprocess.check_output(cmd, shell=True, text=True)
            return f'<pre>{result}</pre>'
        except Exception as e:
            return f'Error: {str(e)}'
    return 'No command provided'

# Эндпоинт для симуляции майнинга
@app.route('/start_mining')
def start_mining():
    # Симулируем высокую нагрузку
    for i in range(1000000):
        _ = i ** 2
    return 'Mining simulation started'

# Доступ к секретам
@app.route('/secrets')
def get_secrets():
    try:
        with open('/app/secrets.txt', 'r') as f:
            return f.read()
    except:
        return 'Secrets not found'

# Создание подозрительных файлов
@app.route('/create_file')
def create_file():
    filename = request.args.get('filename', '/tmp/test_file')
    content = request.args.get('content', 'test content')
    
    with open(filename, 'w') as f:
        f.write(content)
    
    return f'File {filename} created'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
