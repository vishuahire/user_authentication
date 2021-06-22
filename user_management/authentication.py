from rest_framework import HTTP_HEADER_ENCODING, authentication
import jwt
#from prac2.settings import DEFAULTS
from django.contrib.auth.models import Group
from user_management.models.user import Users
from django.conf import settings
#from jwtauth.exceptions import AuthenticationFailed
from rest_framework.exceptions import PermissionDenied,AuthenticationFailed
from user_management.models.user import UserActiveLoggedIn
from rest_framework.response import Response
import sys
from rest_framework import status
from user_management.models.exception import ExceptionError
from django.utils.translation import ugettext_lazy as _


AUTH_HEADER_TYPES = ('Bearer', )

if not isinstance(AUTH_HEADER_TYPES, (list, tuple)):
    AUTH_HEADER_TYPES = (AUTH_HEADER_TYPES, )

AUTH_HEADER_TYPE_BYTES = set(
    h.encode(HTTP_HEADER_ENCODING) for h in AUTH_HEADER_TYPES)


class JWTAuthentication(authentication.BaseAuthentication):
    """
    An authentication plugin that authenticates requests through a JSON web
    token provided in a request header.
    """
    www_authenticate_realm = 'api'

    def authenticate_header(self, request):
        return '{0} realm="{1}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header,request)
        if raw_token is None:
            
            response = {'status': "error",'message':PermissionDenied(),'status_code':status.HTTP_403_FORBIDDEN}
            ExceptionError.objects.create(http_status=status.HTTP_403_FORBIDDEN,api_url= request.get_host() + request.get_full_path() ,error_message=PermissionDenied())
            raise PermissionDenied(response)

        validated_token = self.get_validated_token(raw_token,request)     
        return self.get_user(validated_token), validated_token

    def get_header(self, request):
        
        header = request.META.get('HTTP_AUTHORIZATION')        
        
        if header is None:
            
            response = {'status': "error",'message':PermissionDenied(),'status_code':status.HTTP_403_FORBIDDEN}
            ExceptionError.objects.create(http_status=status.HTTP_403_FORBIDDEN,api_url= request.get_host() + request.get_full_path() ,error_message=PermissionDenied())
            raise PermissionDenied(response)

        if isinstance(header, str):
            # Work around django test client oddness
            header = header.encode(HTTP_HEADER_ENCODING)
        return header

    def get_raw_token(self, header,request):
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts = header.split()
        
        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None
        if parts[0] not in AUTH_HEADER_TYPE_BYTES:
            # Assume the header does not contain a JSON web token
            return None
        if len(parts) != 2:
            raise AuthenticationFailed(
                _('Authorization header must contain two space-delimited values'
                  ),
                code='bad_authorization_header',
            )
        return parts[1]

    def get_validated_token(self, raw_token,request):
        if raw_token is None:
            response = {'status': "error",'message':PermissionDenied(),'status_code':status.HTTP_403_FORBIDDEN}
            ExceptionError.objects.create(http_status=status.HTTP_403_FORBIDDEN, api_url= request.get_host() + request.get_full_path(),error_message=PermissionDenied())
            raise PermissionDenied(response)
        """
        Validates an encoded JSON web token and returns a validated token
        wrapper object.
        """    
        
        if not UserActiveLoggedIn.objects.filter(token=raw_token).exists():
            response = {'status': "error",'message':PermissionDenied(),'status_code':status.HTTP_403_FORBIDDEN}
            ExceptionError.objects.create(http_status=status.HTTP_403_FORBIDDEN,api_url= request.get_host() + request.get_full_path() ,error_message=PermissionDenied())
            raise PermissionDenied(response)

        try:
            token = jwt.decode(raw_token,settings.SECRET_KEY)
            
            return token
        except :
            response = {'status': "error",'message':PermissionDenied(),'status_code':status.HTTP_403_FORBIDDEN}
            ExceptionError.objects.create(http_status=status.HTTP_403_FORBIDDEN,api_url= request.get_host() + request.get_full_path() ,error_message=PermissionDenied())
            raise PermissionDenied(response)
    def get_user(self,validated_token):   
        try:
            user_id = validated_token['id']
            user = Users.objects.get(id=user_id)
            if user == None:
                raise AuthenticationFailed(_('Invalid credentials'),
                                        code='invalid_credentials')
            else:
                return user
        except KeyError:
            res = {'error': 'The given token is invalid, please log-in again'}
            return res 
 