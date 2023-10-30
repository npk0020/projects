from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

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

#generate 2 keys, 1 for expired parameter
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,

)

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

numbers = private_key.private_numbers()

#set exp dates for keys
pem_exp = int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
expired_pem_exp = int((datetime.datetime.utcnow() - datetime.timedelta(hours=6)).timestamp()) 

#helper function for database insert
def insert_into_database(func_key, func_exp):
        cursor.execute(''' INSERT INTO  keys (key, exp)  VALUES (?, ?)''', (func_key, func_exp))
        #committ changes to db
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

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
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
