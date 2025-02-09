import secrets
from flask import Flask, request, g
from flask_restx import Api, Resource, fields # type: ignore
from functools import wraps
from .db import get_connection, init_db
import logging
from app.custom_logger import CustomLogger


# Define a simple in-memory token store
tokens = {}

# Creando instancia de CustomLogger
logger = CustomLogger(log_file="application.log")

# Configure Swagger security scheme for Bearer tokens
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Enter your token in the format **Bearer <token>**"
    }
}

app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias, incluyendo autenticación y operaciones de cuenta.',
    doc='/swagger',  # Swagger UI endpoint
    authorizations=authorizations,
    security='Bearer'
)

# Create namespaces for authentication and bank operations
auth_ns = api.namespace('auth', description='Operaciones de autenticación')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# Define the expected payload models for Swagger
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
    'password': fields.String(required=True, description='Contraseña', example='pass1')
})

deposit_model = bank_ns.model('Deposit', {
    'account_number': fields.Integer(required=True, description='Número de cuenta', example=123),
    'amount': fields.Float(required=True, description='Monto a depositar', example=100)
})

withdraw_model = bank_ns.model('Withdraw', {
    'amount': fields.Float(required=True, description='Monto a retirar', example=100)
})

transfer_model = bank_ns.model('Transfer', {
    'target_username': fields.String(required=True, description='Usuario destino', example='user2'),
    'amount': fields.Float(required=True, description='Monto a transferir', example=100)
})

credit_payment_model = bank_ns.model('CreditPayment', {
    'amount': fields.Float(required=True, description='Monto de la compra a crédito', example=100)
})

pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
    'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
})

# ---------------- Authentication Endpoints ----------------

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    @auth_ns.doc('login')
    def post(self):
        """Inicia sesión y devuelve un token de autenticación."""
        data = api.payload
        username = data.get("username")
        password = data.get("password")

        ip_address = request.remote_addr
        
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, username, password, role, full_name, email FROM bank.users WHERE username = %s", (username,))
        user = cur.fetchone()
        if user and user[2] == password:
            token = secrets.token_hex(16)
            # Persist the token in the database
            cur.execute("INSERT INTO bank.tokens (token, user_id) VALUES (%s, %s)", (token, user[0]))
            conn.commit()
            cur.close()
            conn.close()
            logger.info(ip_address, username, "Login successful", 200)
            return {"message": "Login successful", "token": token}, 200
        else:
            cur.close()
            conn.close()
            logger.error(ip_address, username, "Failed login attempt", 401)
            api.abort(401, "Invalid credentials")

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout')
    def post(self):
        """Invalida el token de autenticación."""
        ip_address = request.remote_addr
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        token = auth_header.split(" ")[1]
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM bank.tokens WHERE token = %s", (token,))
        if cur.rowcount == 0:
            conn.commit()
            cur.close()
            conn.close()
            logger.error(ip_address, "Unknown", f"Invalid token attempt: {token}", 401)
            api.abort(401, "Invalid token")
        conn.commit()
        cur.close()
        conn.close()
        logger.info(ip_address, "Unknown", f"Logout successful for token: {token}", 200)
        return {"message": "Logout successful"}, 200

# ---------------- Token-Required Decorator ----------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip_address = request.remote_addr
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            api.abort(401, "Authorization header missing or invalid")
        token = auth_header.split(" ")[1]
        logger.debug(ip_address, "Unknown", f"Token received: {token}", 200)
        conn = get_connection()
        cur = conn.cursor()
        # Query the token in the database and join with users table to retrieve user info
        cur.execute("""
            SELECT u.id, u.username, u.role, u.full_name, u.email 
            FROM bank.tokens t
            JOIN bank.users u ON t.user_id = u.id
            WHERE t.token = %s
        """, (token,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if not user:
            logger.error(ip_address, "Unknown", f"Invalid or expired token: {token}", 401)
            api.abort(401, "Invalid or expired token")
        g.user = {
            "id": user[0],
            "username": user[1],
            "role": user[2],
            "full_name": user[3],
            "email": user[4]
        }
        return f(*args, **kwargs)
    return decorated

# ---------------- Banking Operation Endpoints ----------------

@bank_ns.route('/deposit')
class Deposit(Resource):
    @bank_ns.expect(deposit_model, validate=True)
    @bank_ns.doc('deposit')
    @token_required
    def post(self):
        """
        Realiza un depósito en la cuenta especificada.
        Se requiere el número de cuenta y el monto a depositar.
        """
        ip_address = request.remote_addr
        data = api.payload
        account_number = data.get("account_number")
        amount = data.get("amount", 0)
        logger.debug(ip_address, g.user['username'], "Entering deposit function", 200)
        if amount <= 0:
            logger.warning(ip_address, g.user['username'], "Invalid amount: must be greater than zero", 400)
            api.abort(400, "Amount must be greater than zero")
        
        conn = get_connection()
        cur = conn.cursor()
        logger.debug(ip_address, g.user['username'], f"Attempting to deposit {amount} to account {account_number}", 200)
        # Update the specified account using its account number (primary key)
        cur.execute(
            "UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance",
            (amount, account_number)
        )
        result = cur.fetchone()
        if not result:
            conn.rollback()
            cur.close()
            conn.close()
            logger.error(ip_address, g.user['username'], f"Account not found: {account_number}", 404)
            api.abort(404, "Account not found")
        new_balance = float(result[0])
        conn.commit()
        cur.close()
        conn.close()
        logger.info(ip_address, g.user['username'], f"Deposit successful. Account: {account_number}, Amount: {amount}, New Balance: {new_balance}", 200)
        return {"message": "Deposit successful", "new_balance": new_balance}, 200

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(withdraw_model, validate=True)
    @bank_ns.doc('withdraw')
    @token_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        ip_address = request.remote_addr
        data = api.payload
        amount = data.get("amount", 0)
        logger.debug(ip_address, g.user['username'], "Entering withdraw function", 200)
        if amount <= 0:
            logger.warning(ip_address, g.user['username'], "Invalid amount: must be greater than zero", 400)
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            logger.error(ip_address, g.user['username'], "Account not found", 404)
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        current_balance = float(row[0])
        if current_balance < amount:
            logger.error(ip_address, g.user['username'], f"Insufficient funds. Current balance: {current_balance}, Requested amount: {amount}", 400)
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds")
        cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", (amount, user_id))
        new_balance = float(cur.fetchone()[0])
        conn.commit()
        cur.close()
        conn.close()
        logger.info(ip_address, g.user['username'], f"Withdrawal successful. Amount: {amount}, New Balance: {new_balance}", 200)
        return {"message": "Withdrawal successful", "new_balance": new_balance}, 200

@bank_ns.route('/transfer')
class Transfer(Resource):
    @bank_ns.expect(transfer_model, validate=True)
    @bank_ns.doc('transfer')
    @token_required
    def post(self):
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta."""
        ip_address = request.remote_addr
        data = api.payload
        target_username = data.get("target_username")
        amount = data.get("amount", 0)
        logger.debug(ip_address, g.user['username'], "Entering transfer function", 200)
        if not target_username or amount <= 0:
            logger.warning(ip_address, g.user['username'], "Invalid data: Target username or amount is missing/invalid", 400)
            api.abort(400, "Invalid data")
        if target_username == g.user['username']:
            logger.warning(ip_address, g.user['username'], "Cannot transfer to the same account", 400)
            api.abort(400, "Cannot transfer to the same account")
        conn = get_connection()
        cur = conn.cursor()
        # Check sender's balance
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
        row = cur.fetchone()
        if not row:
            logger.error(ip_address, g.user['username'], "Sender account not found", 404)
            cur.close()
            conn.close()
            api.abort(404, "Sender account not found")
        sender_balance = float(row[0])
        if sender_balance < amount:
            logger.error(ip_address, g.user['username'], f"Insufficient funds. Current balance: {sender_balance}, Requested amount: {amount}", 400)
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds")
        # Find target user
        cur.execute("SELECT id FROM bank.users WHERE username = %s", (target_username,))
        target_user = cur.fetchone()
        if not target_user:
            logger.error(ip_address, g.user['username'], f"Target user not found: {target_username}", 404)
            cur.close()
            conn.close()
            api.abort(404, "Target user not found")
        target_user_id = target_user[0]
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, g.user['id']))
            cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", (amount, target_user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            logger.error(ip_address, g.user['username'], f"Error during transfer: {str(e)}", 500)
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, f"Error during transfer: {str(e)}")
        cur.close()
        conn.close()
        logger.info(ip_address, g.user['username'], f"Transfer successful. Amount: {amount}, New Balance: {new_balance}", 200)
        return {"message": "Transfer successful", "new_balance": new_balance}, 200

@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.expect(credit_payment_model, validate=True)
    @bank_ns.doc('credit_payment')
    @token_required
    def post(self):
        """
        Realiza una compra a crédito:
        - Descuenta el monto de la cuenta.
        - Aumenta la deuda de la tarjeta de crédito.
        """
        ip_address = request.remote_addr
        data = api.payload
        amount = data.get("amount", 0)
        logger.debug(ip_address, g.user['username'], "Entering credit payment function", 200)
        if amount <= 0:
            logger.warning(ip_address, g.user['username'], "Invalid amount: Amount must be greater than zero", 400)
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            logger.error(ip_address, g.user['username'], "Account not found", 404)
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            logger.error(ip_address, g.user['username'], f"Insufficient funds in account. Current balance: {account_balance}, Requested amount: {amount}", 400)
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds in account")
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", (amount, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_balance = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            logger.error(ip_address, g.user['username'], f"Error processing credit card purchase: {str(e)}", 500)
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, f"Error processing credit card purchase: {str(e)}")
        cur.close()
        conn.close()
        logger.info(ip_address, g.user['username'], f"Credit payment successful. Amount: {amount}, New Account Balance: {new_account_balance}, New Credit Card Debt: {new_credit_balance}", 200)
        return {
            "message": "Credit card purchase successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_balance
        }, 200

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(pay_credit_balance_model, validate=True)
    @bank_ns.doc('pay_credit_balance')
    @token_required
    def post(self):
        """
        Realiza un abono a la deuda de la tarjeta:
        - Descuenta el monto (o el máximo posible) de la cuenta.
        - Reduce la deuda de la tarjeta de crédito.
        """
        ip_address = request.remote_addr
        data = api.payload
        amount = data.get("amount", 0)
        logger.debug(ip_address, g.user['username'], "Entering credit balance payment function", 200)
        if amount <= 0:
            logger.warning(ip_address, g.user['username'], "Invalid amount: Amount must be greater than zero", 400)
            api.abort(400, "Amount must be greater than zero")
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        # Check account funds
        cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            logger.error(ip_address, g.user['username'], "Account not found", 404)
            cur.close()
            conn.close()
            api.abort(404, "Account not found")
        account_balance = float(row[0])
        if account_balance < amount:
            logger.error(ip_address, g.user['username'], f"Insufficient funds in account. Current balance: {account_balance}, Requested amount: {amount}", 400)
            cur.close()
            conn.close()
            api.abort(400, "Insufficient funds in account")
        # Get current credit card debt
        cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
        if not row:
            logger.error(ip_address, g.user['username'], "Credit card not found", 404)
            cur.close()
            conn.close()
            api.abort(404, "Credit card not found")
        credit_debt = float(row[0])
        payment = min(amount, credit_debt)
        try:
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_debt = float(cur.fetchone()[0])
            conn.commit()
        except Exception as e:
            logger.error(ip_address, g.user['username'], f"Error processing credit balance payment: {str(e)}", 500)
            conn.rollback()
            cur.close()
            conn.close()
            api.abort(500, f"Error processing credit balance payment: {str(e)}")
        cur.close()
        conn.close()
        logger.info(ip_address, g.user['username'], f"Credit balance payment successful. Amount paid: {payment}, New Account Balance: {new_account_balance}, New Credit Card Debt: {new_credit_debt}", 200)
        return {
            "message": "Credit card debt payment successful",
            "account_balance": new_account_balance,
            "credit_card_debt": new_credit_debt
        }, 200

@app.before_first_request
def initialize_db():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

