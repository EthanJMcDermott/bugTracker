from django.shortcuts import redirect

def unauthenticated_user(request):
    def wrapper_func(request):
        try:
            request.session['user_id']
        except:
            return redirect('/login')

