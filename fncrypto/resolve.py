class ResolveException(Exception):
    pass

def _resolve_name(name=None):
    """ 
    Resolve a given string into a referencable object
    @param name string for an object
    """
    if name is None:
        return None
    obj = None
    parts = name.split('.')
    cursor = len(parts)
    module_name = parts[:cursor]
    last_xcp = None
    while cursor > 0:
        try:
            obj = __import__('.'.join(module_name))
            break
        except ImportError, e:
            last_xcp = e
            if cursor == 0:
                raise
            cursor = -1
            module_name = parts[:cursor]
    for part in parts[1:]:
        try:
            obj = getattr(obj, part)
        except AttributeError:
            if last_xcp is not None:
                raise last_xcp
            raise ImportError(name)
    if obj is None:
        if last_xcp is not None:
            raise last_xcp
        raise ImportError(name)
    return obj

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

