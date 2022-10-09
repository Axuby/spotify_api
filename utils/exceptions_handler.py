from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    handlers = {
        'ValidationError': _handle_generic_error,
        'Http404': _handle_generic_error,
        'PermissionDenied': _handle_generic_error,
        'NotAuthenticated': _handle_authentication_error,
    }

    response = exception_handler(exc, context)
    if response is not None:
        # import pdb
        # pdb.set_trace()
        exception_class = exc.__class__.__name__
        response.data["status"] = "fail"

        if exception_class in handlers:
            return handlers[exception_class](exc, context, response)
        return response


def _handle_generic_error(exc, context, response):
    return response


def _handle_authentication_error(exc, context, response):
    response.data = {
        "status": "fail",
        "message": "Please login to access this API"
    }
    return response
