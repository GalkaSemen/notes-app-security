# security.py - ОПТИМИЗИРОВАННЫЙ ВАРИАНТ
from flask import Response
import os

def add_security_headers(response: Response) -> Response:
    """Middleware для добавления HTTP-заголовков безопасности"""
    
    # 1. CSP - оптимальный баланс для учебного проекта
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    
    # 2. Основные защитные заголовки
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # 3. Скрытие информации (только для учебного проекта)
    response.headers['Server'] = 'Protected-Server'
    
    # 4. HSTS - только для production с HTTPS
    # В учебном проекте на HTTP не добавляем
    
    return response

def setup_security(app):
    """Настройка безопасности Flask приложения"""
    
    # Регистрация middleware
    app.after_request(add_security_headers)
    
    # Настройка сессионных cookie
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,    # Защита от XSS
        SESSION_COOKIE_SAMESITE='Lax',   # Защита от CSRF
        SESSION_COOKIE_SECURE=False,     # True только для HTTPS
        PERMANENT_SESSION_LIFETIME=1800  # 30 минут
    )
    
    return app
