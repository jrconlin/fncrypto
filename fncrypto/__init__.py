# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# This is a combination Python library and client test web app.
# The python library of interest is in crypto.py. The calls are
# fairly straight forward and feel free to use whatever wsgi/curl
# like library you feel most comfortable with.

from pyramid.config import Configurator
from mozsvc.config import load_into_settings
from fncrypto.resources import Root
from fncrypto.resolve import configure_from_settings

appname = 'fncrypto'


def main(global_config, **settings):
    config_file = global_config['__file__']
    load_into_settings(config_file, settings)

    config = Configurator(root_factory=Root, settings=settings)

    config.include('cornice')
    config.include('mozsvc')
    config.scan('%s.views' % appname)
    config.registry['storage'] = configure_from_settings(
            'storage', settings['config'].get_map('storage'))

    return config.make_wsgi_app()
