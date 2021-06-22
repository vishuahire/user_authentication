from rest_framework.generics import *
from user_management.authentication import JWTAuthentication
from user_management.serializers.user import *
from user_management.serializers.permissions import *
from user_management.models.permissions import *
from django.db.models import Q
import traceback
import sys
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from user_management.models.exception import ExceptionError
from rest_framework.exceptions import PermissionDenied, AuthenticationFailed
from django.urls import reverse
import json
from datetime import datetime


class UserPermission(ListAPIView):
    """
    get Permission list

    Query parameters for GET method
    ---------------------------------------
    1. is_active = true or false
    2. permission = string
    3. permission_desc = string
    4. id = ID of permission
        
    eg. http://127.0.0.1:8000/users/get-user-permission/

    return - list of permissions
    """
    try:
        # authentication_classes = [JWTAuthentication]
        # queryset = Permissions.all_objects.all()
        serializer_class = UserPermissionserializer

        def list(self, request, *args, **kwargs):
            queryset = self.filter_queryset(self.get_queryset())

            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = self.get_serializer(queryset, many=True)
            response = {'status': "success",'message':serializer.data,'status_code':status.HTTP_200_OK}
            return Response(response)

        def get_queryset(self):
            q_objects = Q()
            queryset = Permissions.all_objects.all().order_by('-id')
            is_active = self.request.GET.get('is_active')
            permission = self.request.GET.get('permission')
            permission_desc = self.request.GET.get('permission_desc')
            permission_id = self.request.GET.get('id')
            
            if is_active :   
                is_active = is_active.strip('\n').strip('\t')
                if is_active == 'All' :
                    q_objects.add(Q(),Q.AND)
                else:
                    q_objects.add(Q(is_active=is_active), Q.AND) 
            else:
                if permission_id:
                    q_objects.add(Q(),Q.AND)
                else:
                    q_objects.add(Q(is_active=True),Q.AND)

            if permission : 
                q_objects.add(Q(permission=permission), Q.AND)
            if permission_desc : 
                q_objects.add(Q(permission_desc=permission_desc), Q.AND)
            if permission_id : 
                q_objects.add(Q(id=permission_id), Q.AND)

            if len(q_objects) > 0 :
                queryset = queryset.filter(q_objects).order_by("-id")    

            return queryset  

    except:
        def generate_error():
            ExceptionError.objects.create(http_status=status.HTTP_403_FORBIDDEN,api_url= None,error_message=sys.exc_info())
            response = {'status': "error",'message':sys.exc_info(),'status_code':status.HTTP_403_FORBIDDEN}
            return Response(response)
        generate_error()
 


class UserCreatePermission(CreateAPIView):
    """
    create permission

    body parameters for POST method
    ---------------------------------------
    1. permission = string
    2. permission_desc = string
    3. created_by = ID of user

    eg. http://127.0.0.1:8000/users/create-permission/
   
    return permission object.
    """
    try:
        # authentication_classes = [JWTAuthentication]
        serializer_class = UserCreatePermissionserializer

        def create(self, request, *args, **kwargs):
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                try:
                    self.perform_create(serializer)
                    headers = self.get_success_headers(serializer.data)
                    response = {'status': "success",'message':serializer.data,'status_code':status.HTTP_201_CREATED}
                    return Response(response, headers=headers)
                except:
                    def generate_error():
                        ExceptionError.objects.create(http_status=status.HTTP_403_FORBIDDEN,api_url= None,error_message=sys.exc_info())
                    generate_error()
            else:
                data = {
                    'api_url':self.request.get_host(),
                    'error_message':serializer.errors,
                    'http_status':status.HTTP_400_BAD_REQUEST
                    }
                response = {'status': "error",'message':serializer.errors,'status_code':status.HTTP_400_BAD_REQUEST}
                ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_400_BAD_REQUEST) 
    except:
        def generate_error():
            ExceptionError.objects.create(http_status=status.HTTP_403_FORBIDDEN,api_url= None,error_message=sys.exc_info())
            response = {'status': "error",'message':sys.exc_info(),'status_code':status.HTTP_403_FORBIDDEN}
            return Response(response)
        generate_error()

    
   

class UpdatePermission(UpdateAPIView):
    """
    update permission

    parameters for PUT/PATCH  method
    --------------------------------------
    1. id - ID of permission

    body parameters for PUT/PATCH method
    ---------------------------------------
    1. is_active = true or false
    2. permission = string
    3. permission_desc = string
    4. last_modified_by = ID of user
  
    eg. http://127.0.0.1:8000/users/update-permission/2

    return permission object.
    """
    try:
        # authentication_classes = [JWTAuthentication]
        serializer_class = UserUpdatePermissionserializer
        # queryset = Permissions.all_objects.all()

        def get_queryset(self):
            if self.request.method == "PATCH":
                is_active = json.loads(self.request.body)
                if is_active['is_active'] == True:
                    queryset = Permissions.all_objects.all().order_by('-id')
                    return queryset
                else:
                    queryset = Permissions.objects.all().order_by('-id')
                    return queryset
            else:
                queryset = Permissions.objects.all().order_by('-id')
                return queryset 


        def update(self, request, *args, **kwargs):
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            instance.last_modified_date = datetime.now()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            if serializer.is_valid():
                # Checks if the data recieved from the user is valid
                # if data is valid, returns 200
                self.perform_update(serializer)

                if getattr(instance, '_prefetched_objects_cache', None):
                    # If 'prefetch_related' has been applied to a queryset, we need to
                    # forcibly invalidate the prefetch cache on the instance.
                    instance._prefetched_objects_cache = {}
                response = {'status': "success",'message':serializer.data,'status_code':status.HTTP_200_OK}
                return Response(response)
            else:
                data = {
                    'api_url':self.request.get_host(),
                    'error_message':serializer.errors,
                    'http_status':status.HTTP_400_BAD_REQUEST
                    }
                response = {'status': "error",'message':serializer.errors,'status_code':status.HTTP_400_BAD_REQUEST}
                ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_400_BAD_REQUEST) 



        def perform_update(self, serializer):
            serializer.save()

        def partial_update(self, request, *args, **kwargs):
            kwargs['partial'] = True
            return self.update(request, *args, **kwargs)

    except:
        def generate_error():
            ExceptionError.objects.create(http_status=status.HTTP_403_FORBIDDEN,api_url= None,error_message=sys.exc_info())
            response = {'status': "error",'message':sys.exc_info(),'status_code':status.HTTP_403_FORBIDDEN}
            return Response(response)
        generate_error()


class DeletePermission(DestroyAPIView):
    """
    delete permission
    
    parameters for DELETE method
    --------------------------------------
    1. id - ID of permission
   
    eg. http://127.0.0.1:8000/users/delete-permission/2

    return none.
    """
    # authentication_classes = [JWTAuthentication]
    serializer_class = UserUpdatePermissionserializer
    queryset = Permissions.all_objects.all()

