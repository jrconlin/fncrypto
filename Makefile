APPNAME = fncrypto
VE = virtualenv
PY = bin/python
PI = bin/pip

all: build

build:
	$(VE) --no-site-packages .
	$(PI) install -r dev-reqs.txt
	$(PY) setup.py build

