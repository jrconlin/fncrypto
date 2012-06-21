# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# This file sends a sample notification to the client. It's useful for
# demonstration, verification and testing, but that's about it.
# If you find this sort of thing useful, let me know and I'll build
# a better demo.
from fncrypto.crypto import FNCrypto
import json
import os
import time
import pycurl
import cStringIO

# A file containing the credentials from the client.
# for testing, I just copied these from
# $UserProfile/jetpack/push@jbalogh.me/simple-storage/store.json
# need "{url: ... , encryptionKey: ..., hmac: ...}"
credFile = './credentials.json'
crypto = FNCrypto

# No credentials, so build a set. (Note, these have to be on
# the client before it can properly decrypt notifications.)
if (not os.path.isfile(credFile)):
    cfile = open(credFile, 'w')
    cfile.write(json.dumps(crypto.generateKeyBundle()))
    cfile.close()
cfile = open(credFile, 'r')
creds = json.loads(' '.join(cfile.readlines()))

# The encrypted content:
testPhrase = json.dumps({'title': 'python test succeeded',
    'body': 'This is a test of the emergency broadcasting'
        ' service, this is only a test',
    'actionUrl': 'http://example.com'})
cryptoBlock = crypto.encrypt(testPhrase, creds)

# The unencrypted wrapper:
sendData = json.dumps({'title': 'python test',
    'body': 'test failed',
    'time': int(time.time()),
    'cryptoBlock': json.dumps(cryptoBlock)})

# print "%s" % json.dumps(result)
print "Sending data...\n"
buf = cStringIO.StringIO()

# send the data to the server
c = pycurl.Curl()
c.setopt(c.URL, str(creds['url']))
c.setopt(c.CONNECTTIMEOUT, 2)
c.setopt(c.WRITEFUNCTION, buf.write)
c.setopt(c.TIMEOUT, 4)
c.setopt(c.HTTPHEADER, ['Content-Type: application/json'])
c.setopt(c.POSTFIELDS, sendData)
try:
    c.perform()
    result = json.loads(buf.getvalue())
    if 'ok' in result['status']:
        print "Success"
    else:
        print "Error recv'ing data: %s " % result['error']
except pycurl.error, e:
    print "Error sending data : %s" % e
