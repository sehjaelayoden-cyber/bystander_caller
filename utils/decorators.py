# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Ikhlas

from functools import wraps
from flask import make_response

def prevent_back_navigation(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return decorated_function