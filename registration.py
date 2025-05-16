from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from .base import BaseHandler

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes #Loads in the required package from cryptography hazmat package
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt #This is importing the decryption functions into the code
from api.conf import EncryptionKey #This is importing the encryption Key from the config file
from api.hashing import hashed_passphrase

class RegistrationHandler(BaseHandler):

    def encrypt_function(self, plaintext, Key):
        IV = os.urandom(16) # Will generate the IV Here

        key_bytes = Key if isinstance(Key, bytes) else Key.encode('utf-8')

    
        padder = padding.PKCS7(128).padder() #Adding padding 
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        aes_cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(IV))
        encryptor = aes_cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return IV + encrypted_data

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)

            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()

            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            
            #Adding Password hash with this function
            hashed_password = hashed_passphrase(password)

            display_name = body.get('displayName')
            if not display_name:
                display_name = email

            address = body.get('address', '')
            if not isinstance(address, str):
                raise Exception()

            DOB = body.get('DOB', '')
            if not isinstance(DOB, str):
                raise Exception()

            phone_number = body.get('phoneNumber', '')
            if not isinstance(phone_number, str):
                raise Exception()

            disability = body.get('disability', '')
            if not isinstance(disability, str):
                raise Exception()

        except Exception as e:
            info(f"Validation error: {str(e)}")  
            self.send_error(400, message='You must provide Personal details!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        #Where data is to be encrypted before being passed to the database
        Encrypted_display_name = self.encrypt_function(display_name, EncryptionKey)
        Encrypted_address = self.encrypt_function(address, EncryptionKey)
        Encrypted_DOB = self.encrypt_function(DOB, EncryptionKey)
        Encrypted_phone_number = self.encrypt_function(phone_number, EncryptionKey)
        Encrypted_disability = self.encrypt_function(disability, EncryptionKey)
        

    
        yield self.db.users.insert_one({
            'email': email,
            'password': hashed_password,
            'displayName': Encrypted_display_name, 
            'address': Encrypted_address,
            'DOB': Encrypted_DOB,
            'phone_number': Encrypted_phone_number,
            'disability': Encrypted_disability,
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
