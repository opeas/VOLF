def get_username(request):
    return {'username': request.user.username if request.user.is_authenticated else 'My account'}