import os
import jwt
import time
from flask import Flask, request, jsonify
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

app = Flask(__name__)


#initialize an empty list to store keys
keys = []

 
#function to generate RSA key pair with kid and expiry
def generate_key(expired):

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    #set expiry based on expired_param
    if expired:
        expiry = int(time.time()) - 3600

    else:
        expiry = int(time.time()) + 3600 

    #append key
    kid = os.urandom(8).hex()
    keys.append({'kid': kid, 'key': private_key, 'expiry': expiry})

    return kid, private_key


#endpoint for serving JWKS
@app.route('/.well-known/jwks.json', methods=['GET'])

def jwks():

    current_time = int(time.time())
    jwks_keys = []

    for key in keys:
        if key['expiry'] > current_time:

            #jwk display logic
            jwk = {
                'kid': key['kid'],
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': str(key['key'].public_key().public_numbers().n),
                'e': str(key['key'].public_key().public_numbers().e)
            }

            jwks_keys.append(jwk)

    return jsonify(keys=jwks_keys)



#endpoint for authentication and JWT issuance
@app.route('/auth', methods=['POST'])

def authenticate():

    expired_param = request.args.get('expired')
    current_time = int(time.time())

    #pass expired param, return based on boolean value
    kid, private_key = generate_key(expired_param)
    
    #set expiry based on expired_param
    if expired_param:
        expiry = int(time.time()) - 3600

    else:
        expiry = int(time.time()) + 3600 


    payload = {

        'username': 'userABC',
        'password': 'password123',
        'iat': current_time,
        'exp': expiry

    }

    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': kid})

    return token #jsonify(token=token)   

 


if __name__ == '__main__':

    app.run(port=8080)

 #write to an endpoint using the public key to validate the JWT 