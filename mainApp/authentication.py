from rest_framework.authentication import CSRFCheck
from rest_framework import exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings

def enforce_csrf(request):
    csrfchecker = CSRFCheck()
    csrfchecker.process_request(request)
    reason = csrfchecker.process_view(request, None, (), {})
    if reason:
        raise exceptions.PermissionDenied('CSRF Failed due to : %s' % reason)

class CustomAuthentication(JWTAuthentication):
    def authenticate(self, request):
        header = self.get_header(request)
        
        if header is None:
            token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE']) or None
        else:
            token = self.get_raw_token(header)
        if token is None:
            return None
        print('hell')
        val_token = self.get_validated_token(token)
        enforce_csrf(request)
        return self.get_user(val_token), val_token