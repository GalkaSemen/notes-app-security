#!/usr/bin/env python3
"""
SIEM Lite - Система мониторинга безопасности для Flask и PostgreSQL
Практическая работа №7
"""

import os
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading

class Config:
    LOG_PATHS = {
        'flask': '/mnt/c/Users/Галина/Desktop/notes_app_pr4/flask_app.log',
        'postgresql': f'/var/log/postgresql/postgresql-{datetime.now().strftime("%Y-%m-%d")}.log',
        'security_alerts': '/mnt/c/Users/Галина/Desktop/notes_app_pr4/security_alerts.log',
        'daily_report': '/mnt/c/Users/Галина/Desktop/notes_app_pr4/daily_security_report.txt'
    }
    
    PATTERNS = {
        'sql_injection': [
            r"'.*OR.*1.*=.*1",
            r"UNION.*SELECT",
            r"DROP.*TABLE",
            r"DELETE.*FROM",
            r"INSERT.*INTO",
            r"';.*--",
        ],
        'suspicious_endpoints': [
            r'/admin',
            r'/api/delete',
            r'/config',
            r'/\.env',
            r'/phpmyadmin',
            r'/wp-admin',
        ]
    }
    
    THRESHOLDS = {
        'failed_logins_per_minute': 5,
        'suspicious_404_per_hour': 20,
        'sql_alert_window_minutes': 5
    }

class LogMonitor:
    def __init__(self):
        self.failed_logins = defaultdict(lambda: deque(maxlen=100))
        self.suspicious_404s = defaultdict(lambda: deque(maxlen=100))
        self.sql_alerts = defaultdict(lambda: deque(maxlen=50))
        self.stats = defaultdict(int)
        self.running = True
    
    def tail_file(self, filename, callback):
        """Чтение логов в реальном времени"""
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, 2)  # В конец файла
                
                while self.running:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    callback(line.strip())
        except Exception as e:
            print(f"❌ Ошибка чтения файла {filename}: {e}")
    
    def process_flask_log(self, line):
        """Обработка логов Flask"""
        self.stats['flask_lines'] += 1
        
        # Простой парсинг Flask логов
        if 'AUTH_ATTEMPT' in line:
            # Извлекаем IP из лога
            ip_match = re.search(r'IP:([\d\.]+)', line)
            if ip_match:
                ip = ip_match.group(1)
                timestamp = datetime.now()
                self.failed_logins[ip].append(timestamp)
                
                # Проверяем брутфорс
                minute_ago = timestamp - timedelta(minutes=1)
                recent = [t for t in self.failed_logins[ip] if t > minute_ago]
                
                if len(recent) >= Config.THRESHOLDS['failed_logins_per_minute']:
                    self.handle_incident({
                        'type': 'FAILED_LOGIN_BRUTEFORCE',
                        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                        'ip': ip,
                        'count': len(recent),
                        'message': f'Обнаружено {len(recent)} неудачных попыток входа за 1 минуту',
                        'severity': 'HIGH'
                    })
        
        # Проверяем доступ к защищенным эндпоинтам
        for endpoint in Config.PATTERNS['suspicious_endpoints']:
            if endpoint in line and ('404' in line or 'GET' in line):
                ip_match = re.search(r'IP:([\d\.]+)', line)
                if ip_match:
                    ip = ip_match.group(1)
                    timestamp = datetime.now()
                    self.suspicious_404s[ip].append(timestamp)
                    
                    hour_ago = timestamp - timedelta(hours=1)
                    recent = [t for t in self.suspicious_404s[ip] if t > hour_ago]
                    
                    if len(recent) >= Config.THRESHOLDS['suspicious_404_per_hour']:
                        self.handle_incident({
                            'type': 'SCANNING_ATTEMPT',
                            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                            'ip': ip,
                            'count': len(recent),
                            'message': f'Обнаружено сканирование: {len(recent)} запросов к {endpoint}',
                            'severity': 'MEDIUM'
                        })
    
    def process_postgresql_log(self, line):
        """Обработка логов PostgreSQL"""
        self.stats['postgresql_lines'] += 1
        
        # Проверяем SQL-инъекции
        for pattern in Config.PATTERNS['sql_injection']:
            if re.search(pattern, line, re.IGNORECASE):
                # Извлекаем IP клиента
                client_match = re.search(r'client=([\d\.]+)', line)
                ip = client_match.group(1) if client_match else 'unknown'
                
                timestamp = datetime.now()
                self.sql_alerts[ip].append(timestamp)
                
                # Проверяем частоту
                window = Config.THRESHOLDS['sql_alert_window_minutes']
                window_start = timestamp - timedelta(minutes=window)
                recent = [t for t in self.sql_alerts[ip] if t > window_start]
                
                incident = {
                    'type': 'SQL_INJECTION_ATTEMPT',
                    'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'ip': ip,
                    'query': line[:200],
                    'pattern': pattern,
                    'severity': 'CRITICAL' if len(recent) >= 3 else 'HIGH'
                }
                
                if len(recent) >= 3:
                    incident['message'] = f'Обнаружено {len(recent)} SQL-инъекций за {window} минут'
                else:
                    incident['message'] = 'Обнаружена попытка SQL-инъекции'
                
                self.handle_incident(incident)
                break
    
    def handle_incident(self, incident):
        """Обработка инцидента"""
        self.stats['incidents'] += 1
        self.stats[incident['type']] += 1
        
        # 1. Запись в файл
        with open(Config.LOG_PATHS['security_alerts'], 'a', encoding='utf-8') as f:
            f.write(f"[{incident['timestamp']}] [{incident['type']}] [{incident['severity']}] IP={incident['ip']} - {incident['message']}\n")
        
        # 2. Вывод в консоль
        colors = {'CRITICAL': '\033[91m', 'HIGH': '\033[31m', 'MEDIUM': '\033[33m', 'LOW': '\033[34m', 'END': '\033[0m'}
        color = colors.get(incident['severity'], colors['END'])
        
        print(f"{color}⚠️  ИНЦИДЕНТ: {incident['type']} | IP: {incident['ip']} | {incident['message']}{colors['END']}")
    
    def generate_report(self):
        """Генерация отчета"""
        report = f"""
==================================================
ЕЖЕДНЕВНЫЙ ОТЧЕТ ПО БЕЗОПАСНОСТИ
Дата: {datetime.now().strftime('%Y-%m-%d')}
Время генерации: {datetime.now().strftime('%H:%M:%S')}
==================================================

СТАТИСТИКА:
  Обработано логов Flask: {self.stats.get('flask_lines', 0)}
  Обработано логов PostgreSQL: {self.stats.get('postgresql_lines', 0)}
  Всего инцидентов: {self.stats.get('incidents', 0)}

РАСПРЕДЕЛЕНИЕ ИНЦИДЕНТОВ:"""
        
        for key in ['FAILED_LOGIN_BRUTEFORCE', 'SQL_INJECTION_ATTEMPT', 'SCANNING_ATTEMPT']:
            if key in self.stats:
                report += f"\n  {key}: {self.stats[key]}"
        
        report += "\n\n==================================================\n"
        
        with open(Config.LOG_PATHS['daily_report'], 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\n✅ Отчет сохранен: {Config.LOG_PATHS['daily_report']}")
        print(report)
    
    def run(self):
        """Запуск мониторинга"""
        print("🚀 SIEM Lite запущен...")
        print(f"📊 Мониторю файлы:")
        print(f"  • Flask: {Config.LOG_PATHS['flask']}")
        print(f"  • PostgreSQL: {Config.LOG_PATHS['postgresql']}")
        print(f"  • Инциденты: {Config.LOG_PATHS['security_alerts']}")
        print("\nДля остановки нажмите Ctrl+C\n")
        
        # Запуск потоков
        threads = []
        
        flask_thread = threading.Thread(
            target=self.tail_file,
            args=(Config.LOG_PATHS['flask'], self.process_flask_log),
            daemon=True
        )
        threads.append(flask_thread)
        
        postgresql_thread = threading.Thread(
            target=self.tail_file,
            args=(Config.LOG_PATHS['postgresql'], self.process_postgresql_log),
            daemon=True
        )
        threads.append(postgresql_thread)
        
        for thread in threads:
            thread.start()
        
        try:
            while self.running:
                time.sleep(1)
                # Каждые 30 секунд показываем статус
                if int(time.time()) % 30 == 0:
                    print(f"📈 Статус: Flask={self.stats.get('flask_lines', 0)}, PostgreSQL={self.stats.get('postgresql_lines', 0)}, Инциденты={self.stats.get('incidents', 0)}")
        except KeyboardInterrupt:
            print("\n🛑 Остановка SIEM монитора...")
            self.running = False
            self.generate_report()

if __name__ == '__main__':
    monitor = LogMonitor()
    monitor.run()
