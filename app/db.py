import os
import psycopg2
import bcrypt  # Para hashear contraseñas

# Variables de entorno (definidas en docker-compose o con valores por defecto)
DB_HOST = os.environ.get('POSTGRES_HOST', 'db')
DB_PORT = os.environ.get('POSTGRES_PORT', '5432')
DB_NAME = os.environ.get('POSTGRES_DB', 'corebank')
DB_USER = os.environ.get('POSTGRES_USER', 'postgres')
DB_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'postgres')

def get_connection():
    """Establece una conexión con la base de datos PostgreSQL"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        return conn
    except Exception as e:
        print(f"Error al conectar con la base de datos: {e}")
        return None

def init_db():
    """Inicializa las tablas y los datos de ejemplo en la base de datos"""
    conn = get_connection()
    if conn is None:
        return
    
    try:
        with conn.cursor() as cur:
            # Crear esquema y tablas
            cur.execute("""
            CREATE SCHEMA IF NOT EXISTS bank AUTHORIZATION postgres;
            
            CREATE TABLE IF NOT EXISTS bank.users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                full_name TEXT,
                email TEXT,
                password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- Se agrega la columna
            );
            """)
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS bank.accounts (
                id SERIAL PRIMARY KEY,
                balance NUMERIC NOT NULL DEFAULT 0,
                user_id INTEGER REFERENCES bank.users(id)
            );
            """)
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS bank.credit_cards (
                id SERIAL PRIMARY KEY,
                limit_credit NUMERIC NOT NULL DEFAULT 1,
                balance NUMERIC NOT NULL DEFAULT 0,
                user_id INTEGER REFERENCES bank.users(id)
            );
            """)
            
            cur.execute("""
            CREATE TABLE IF NOT EXISTS bank.tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER REFERENCES bank.users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """)
            
            conn.commit()  # Hacer commit después de crear las tablas
            
            # Insertar datos de ejemplo si no existen usuarios
            cur.execute("SELECT COUNT(*) FROM bank.users;")
            count = cur.fetchone()[0]
            if count == 0:
                sample_users = [
                    ('user1', 'Pass1@123', 'cliente', 'Usuario Uno', 'user1@example.com'),
                    ('user2', 'Pass2@123', 'cliente', 'Usuario Dos', 'user2@example.com'),
                    ('user3', 'Pass3@123', 'cajero',  'Usuario Tres', 'user3@example.com')
                ]
                for username, password, role, full_name, email in sample_users:
                    # Hasheamos la contraseña antes de insertarla
                    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                    cur.execute("""
                        INSERT INTO bank.users (username, password, role, full_name, email)
                        VALUES (%s, %s, %s, %s, %s) RETURNING id;
                    """, (username, hashed_password, role, full_name, email))
                    user_id = cur.fetchone()[0]
                    
                    # Crear una cuenta con saldo inicial 1000
                    cur.execute("""
                        INSERT INTO bank.accounts (balance, user_id)
                        VALUES (%s, %s);
                    """, (1000, user_id))
                    
                    # Crear una tarjeta de crédito con límite 5000 y deuda 0
                    cur.execute("""
                        INSERT INTO bank.credit_cards (limit_credit, balance, user_id)
                        VALUES (%s, %s, %s);
                    """, (5000, 0, user_id))
                
                conn.commit()  # Hacer commit después de insertar los datos de ejemplo
    except Exception as e:
        print(f"Error al inicializar la base de datos: {e}")
    finally:
        conn.close()

