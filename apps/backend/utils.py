import logging

from django.db.utils import  OperationalError,ProgrammingError

from .models import CustomUserModel

logger = logging.getLogger(__name__)


def _get_dict_errors(errors):
    """
    Method to get the error messages from the serializer errors' dict structure.
    """
    response = {}
    for key, value in errors.items():
        string_list = [str(i) for i in value]
        response[key] = string_list
    return response


def format_serializer_errors(errors):
    """
    Method to get the errors' final structure based on the serializer errors and depending on the sructure
    received (it can be a list of error structures or a dict).
    """
    if isinstance(errors, dict):
        return _get_dict_errors(errors)
    elif isinstance(errors, list):
        response = []
        for item in errors:
            response.append(_get_dict_errors(item))
        return response

    else:
        return {"Unknown Error"}