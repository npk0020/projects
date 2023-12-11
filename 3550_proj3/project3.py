from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
from argon2 import PasswordHasher
from Crypto.Cipher import AES
import os
#unit testing only conducted on code, I added. 
#majority of the jwks web server was written by my instructor
#most of what is commented is what I wrote


hostName = "localhost"
serverPort = 8080

#create/open the SQLite database file
conn= sqlite3.connect("totally_not_my_privateKeys.db")
cursor = conn.cursor()


#define the table schema (if not exists)
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP      
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,  
    FOREIGN KEY(user_id) REFERENCES users(id)
);
''')

# Initialize password hasher for Argon2
password_hasher = PasswordHasher()

# Function to hash a password using Argon2
def hash_password(password):
    return password_hasher.hash(password)

#generate 2 keys, 1 for expired parameter
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,

)

#Get key from environment
encryption_key = os.getenv('NOT_MY_KEY')
#Check if the encryption key is available
if encryption_key is None:
    raise ValueError("Encryption key not found in environment variables")

#encode both keys to pem
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)


#AES encryption function
def encrypt_private_key(private_key):
    cipher = AES.new(encryption_key.encode(), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key)
    return ciphertext, cipher.nonce, tag

#AES decryption function
def decrypt_private_key(encrypted_key, nonce, tag):
    cipher = AES.new(encryption_key.encode(), AES.MODE_EAX, nonce=nonce)
    decrypted_key = cipher.decrypt_and_verify(encrypted_key, tag)
    return decrypted_key

#encrypt private key
encrypted_pem, nonce, tag = encrypt_private_key(pem)

numbers = private_key.private_numbers()

#set exp dates for keys
pem_exp = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
expired_pem_exp = int((datetime.datetime.utcnow() - datetime.timedelta(hours=6)).timestamp()) 

#helper function for database insert
def insert_into_database(func_key, func_exp):
        cursor.execute(''' INSERT INTO  keys (key, exp)  VALUES (?, ?)''', (func_key, func_exp))
        #committ changes to db
        conn.commit()


# Store encrypted_pem, nonce, and tag in the database
cursor.execute(''' INSERT INTO keys (encrypted_key, nonce, tag) VALUES (?, ?, ?)''', (encrypted_pem, nonce, tag))
conn.commit()

#insert data into database
insert_into_database(pem, pem_exp)
insert_into_database(expired_pem, expired_pem_exp)



def test_insert_case():
    insert_into_database(pem, pem_exp)
    test_var_key = cursor.execute('''SELECT key FROM keys WHERE kid = 3''')
    test_key = test_var_key.fetchone()
    test_var_exp = cursor.execute('''SELECT exp FROM keys WHERE kid = 3''')
    test_exp = test_var_exp.fetchone()
    assert test_key[0] ==  pem, "key does not match test case"
    assert test_exp[0] == pem_exp, "key expiration date does not match test case" 


#function to convert an integer value to base64
def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


#class to handle server requests
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    #/auth endpoint
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)

            # Get user ID from the username (You'll need to adjust this logic based on how you handle user authentication)
            cursor.execute('''SELECT user_id FROM users WHERE user_id = ?''')
            user_id= cursor.fetchone()   #TODO:Replace this with the actual user ID retrieved from the database

            # Log details into the auth_logs table
            request_ip = self.client_address[0]  # Get the client's IP address
            request_timestamp = datetime.utcnow()
            
            cursor.execute(''' INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)''', (request_ip, request_timestamp, user_id))
            conn.commit()

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    #/register endpoint
    def do_POST(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))

            if 'username' not in data or 'email' not in data:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Please provide both username and email'}).encode('utf-8'))
                return

            username = data['username']
            email = data['email']

            # Generate a secure password using UUIDv4
            generated_password = str(uuid.uuid4())

            # Hash the generated password using Argon2
            hashed_password = hash_password(generated_password)

            # Store user details and hashed password in the database
            cursor.execute(''' INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)''', (username, hashed_password, email))
            conn.commit()

            # Return the generated password to the user
            response_data = {'password': generated_password}
            self.send_response(201)
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
            return

        self.send_response(405)
        self.end_headers()
        return

    #get endpoint
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()