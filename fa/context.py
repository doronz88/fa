IDA_MODULE = False

try:
    import idc  # noqa: F401

    IDA_MODULE = True
except ImportError:
    pass


class InvalidContextException(Exception):
    pass


def get_correct_implementation(function_name, params, ida=None, unknown=None,
                               **kwargs):
    """
    Get and execute the correct implementation according to the currently
    executing context
    :param function_name: function name to be executes
    :param params: parameters to pass to function
    :param ida: IDA context implementation
    :param unknown: Unknown context implementation
    :return: The execution result from the correctly running context
    """
    if ida and IDA_MODULE:
        return ida(*params, **kwargs)
    if unknown:
        return unknown(*params, **kwargs)

    raise InvalidContextException(
        'function "{}" must be executed from a specific context'
        .format(function_name))


def verify_ida(function_name):
    if not IDA_MODULE:
        raise InvalidContextException(
            'operation "{}" must be executed from an IDA context'
            .format(function_name))


def ida_context(function):
    if IDA_MODULE:
        return function
    else:
        def invalid_context(*kwargs):
            raise InvalidContextException(
                'function "{}" must be executed from an IDA context'
                .format(function.__name__))
        return invalid_context
