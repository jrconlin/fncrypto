# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
"""
    Main dispatch for request processing
"""
import os
from cornice.service import Service
from fncrypto.crypto import (FNCrypto, FNCryptoException)
from pyramid import httpexceptions as http

# path definitions.
encode = Service(name='encode', path='/encode/')
decode = Service(name='decode', path='/decode/')
guser = Service(name='guser', path='/user/')
user = Service(name='user', path='/user/{uid}')

@encode.post()
def encode(request):
    """
    Encode the notification body using the keys stored for UID 

    @body {'uid': UserID, 
           'plaintext': PlainTextContent
    """
    storage = request.registry['storage']
    crypto = FNCrypto(storage=storage)
    body = request.json_body
    plaintext = body.get('plaintext')
    if isinstance(plaintext, unicode):
        plaintext = plaintext.encode()
    return {'crypto': crypto.encrypt(str(plaintext), 
                uid = body.get('uid')),
              'keyBlock': crypto.getKeyBundle(
                  crypto.getUserToken().get('uid'))}


@decode.post()
def decode(request):
    """
    Decode a given block using the keys stored for UID
    """
    storage = request.registry['storage']
    crypto = FNCrypto(storage=storage)
    body = request.json_body
    try:
        plaintext = crypto.decrypt(body)
    except FNCryptoException, e:
        raise http.HTTPBadRequest(repr(e))
    return {'text': plaintext.encode('utf8')}


def has_token_and_domain(request):
    """Non-empty token and domain values must be give in the POST body."""
    for key in ('token', 'domain'):
        if not request.POST.get(key):
            return 400, 'Missing required argument: ' + key


# Fake user functions. 
# Obviously, these really ought to be using something like BrowserID
# or your own user login functions in order to create a unique ID 
# for a given user. If you're not interested in doing user login, 
# the following will work fine, but again, you probably want to make
# the storage something a bit more durable than an in memory hash.
# 
# Hey, demo app. I can cut corners. 
#
@user.post()
def new_user(request):
    """ add a new user to the Storage """
    storage = request.registry['storage']
    crypto = FNCrypto(storage=storage)
    uid = None
    try:
        body = request.json_body
    except ValueError, e:
        body = {}
        pass
    if 'uid' in body:
        uid = body.get('uid')
    if uid is None:
        # generate a 256bit random fake UID.
        uid = os.urandom(256/8).encode('hex')
        while (uid in storage):
            # that's unique. 
            uid = os.urandom(256/8)
    if uid in storage:
        return storage.get(uid)
    info = crypto.generateKeyBundle(uid)
    info.update({'uid': uid})
    storage[uid] = info
    return info

@user.get()
@guser.get()
def get_user(request):
    storage = request.registry['storage']
    uid = None
    if 'uid' in request.matchdict:
        uid = request.matchdict.get('uid')
    else:
        try:
            body = request.json_body
            uid = body.uid
        except ValueError, e:
            print e;
            pass
        except KeyError, e:
            pass
    if uid in storage:
        return storage[uid]
    return http.HTTPNotFound()

@user.delete()
def kill_user(request):
    storage = request.registry['storage']
    try:
        body = request.json_body
        del storage[body.uid]
    except ValueError, e:
        pass
    except KeyError, e:
        pass
    return True

