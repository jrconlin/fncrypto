"""
    Main dispatch for request processing
"""
import os
from cornice.service import Service
from fncrypto.crypto import (Crypto, CryptoException)
from pyramid import httpexceptions as http


encode = Service(name='encode', path='/encode/')
decode = Service(name='decode', path='/decode/')
user = Service(name='user', path='/user/{uid}')

#
#def has_keys_and_notification(request):
#    """Non-empty keys and notification values must be give in the POST body."""
#    for key in ('keys', 'notification'):
#        if not request.POST.get(key):
#            return 400, 'Missing required argument: ' + key


#@encode.post(validators=has_keys_and_notification)
@encode.post()
def encode(request):
    """
    Encode the notification body using the keys stored for UID 

    @body {'uid': UserID, 
           'plaintext': PlainTextContent
    """
    storage = request.registry['storage']
    crypto = Crypto(storage=storage)
    body = request.json_body
    plaintext = body.get('plaintext')
    if isinstance(plaintext, unicode):
        plaintext = plaintext.encode()
    return crypto.encrypt(str(plaintext), 
                uid = body.get('uid'));


@decode.post()
def decode(request):
    """
    Decode a given block using the keys stored for UID
    """
    storage = request.registry['storage']
    crypto = Crypto(storage=storage)
    body = request.json_body
    try:
        plaintext = crypto.decrypt(body)
    except CryptoException, e:
        raise http.HTTPBadRequest(repr(e))
    return {'text': plaintext.encode('utf8')}


def has_token_and_domain(request):
    """Non-empty token and domain values must be give in the POST body."""
    for key in ('token', 'domain'):
        if not request.POST.get(key):
            return 400, 'Missing required argument: ' + key


#Add authentication to these.
@user.post()
def new_user(request):
    """ add a new user to the Storage """
    storage = request.registry['storage']
    body = request.json_body
    crypto = Crypto(storage=storage)
    uid = body.uid
    if uid is None:
        uid = os.urandom(256)
        while (uid in storage):
            uid = os.urandom(256)
    if uid in storage:
        return storage.get(body.uid)
    info = crypto.generateKeyBundle(body.uid)
    info.update({'uid': uid})
    storage[uid] = info
    return info

@user.get()
def get_user(request):
    storage = request.registry['storage']
    body = request.json_body
    uid = body.uid
    return storage[uid]

@user.delete()
def kill_user(request):
    storage = request.registry['storage']
    body = request.json_body
    del storage[body.uid]
    return True

#@user.put ?

