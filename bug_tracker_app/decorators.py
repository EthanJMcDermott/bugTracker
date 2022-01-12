from django.shortcuts import redirect
import functools

def unauthenticated_user(request, func):
    def wrap(request, *args, **kwargs):
        try:
            request.session['user_id']
            func()
            return wrap
            # return function(request, *args, **kwargs)
        except:
            return redirect('/login')

