import os
import re
from datetime import datetime

class CustomLogger:
    def __init__(self, log_file='application.log'):
        # Inicializa el logger y crea el archivo de logs si no existe.
        self.log_file = log_file

        # Verificar existencia del archivo de logs
        if not os.path.exists(log_file):
            with open(log_file, 'w'):
                pass

    def log(self, log_type, ip_address, username, message, http_code):
        # Valida los parámetros de entrada antes de escribir en el log.
        valid_log_types = {'INFO', 'DEBUG', 'WARNING', 'ERROR'}

        if log_type not in valid_log_types:
            raise ValueError(f"Tipo de log inválido: {log_type}")

        if not isinstance(ip_address, str) or not self.validate_ip(ip_address):
            raise ValueError(f"Dirección IP inválida: {ip_address}")

        if not isinstance(username, str) or len(username.strip()) == 0:
            raise ValueError("El nombre de usuario no puede estar vacío.")

        if not isinstance(message, str) or len(message.strip()) == 0:
            raise ValueError("El mensaje no puede estar vacío.")

        if not isinstance(http_code, int) or not (100 <= http_code <= 599):
            raise ValueError(f"Código HTTP inválido: {http_code}")

        # Enmascara los datos sensibles antes de escribir en el log.
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        masked_ip, masked_username = self.mask_sensitive_data(ip_address, username)

        # Estructura del Log
        log_message = f"{timestamp} | {log_type} | {masked_ip} | {masked_username} | {message} | {http_code}\n"

        with open(self.log_file, 'a') as f:
            f.write(log_message)

    def validate_ip(self, ip):
        # Valida si la dirección IP tiene un formato correcto.
        pattern = r'^((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$'
        return re.match(pattern, ip) is not None

    def mask_sensitive_data(self, ip_address, username):
        # Enmascara la dirección IP y el nombre de usuario.
        masked_ip = '.'.join(ip_address.split('.')[:2]) + ".***.***"
        masked_username = username[0] + "***" + username[-1] if len(username) > 2 else "***"
        return masked_ip, masked_username

    # Métodos helper para registrar mensajes con diferentes niveles de severidad
    def info(self, ip_address, username, message, http_code):
        self.log('INFO', ip_address, username, message, http_code)

    def debug(self, ip_address, username, message, http_code):
        self.log('DEBUG', ip_address, username, message, http_code)

    def warning(self, ip_address, username, message, http_code):
        self.log('WARNING', ip_address, username, message, http_code)

    def error(self, ip_address, username, message, http_code):
        self.log('ERROR', ip_address, username, message, http_code)