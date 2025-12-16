# Конфигурация Gunicorn для ПР3
bind = "0.0.0.0:5000"
workers = 1
worker_class = "sync"
server_software = "SecureNotesServer/1.0"
accesslog = "-"
errorlog = "-"
timeout = 120
preload_app = True
