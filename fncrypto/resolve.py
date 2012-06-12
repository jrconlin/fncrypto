# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
from mozsvc.middlewares import _resolve_name

# configuration parse/scan utility functions. Some brazenly stolen
# from mozsvc.


class ResolveException(Exception):
    pass


def _get_group(group_name, dictionary):
    """
    Get a sub-group from a configuration dictionary

    @param group_name sub-group name to get
    @param dictionary configuration dictionary
    """
    if group_name is None:
        return dictionary
    else:
        result = {}
        trim = len(group_name) + 1
        for key in filter(lambda x: x.startswith(group_name), dictionary):
            result[key[trim:]] = dictionary[key]
        return result


def configure_from_settings(object_name, settings):
    """
        build and configure an object from the settings file

        please use the form
        [Section]
        backend = path.to.object

        @param object_name the name of the object to build.
        @param settings the configuration settings.
    """
    config = dict(settings)
    if 'backend' not in config:
        if '%s.backend' % object_name in config:
            config = _get_group(object_name, config)
        else:
            raise ResolveException("No 'backend' found for section %s." %
                    object_name)
    cls = _resolve_name(config.pop('backend'))
    return cls(**config)
