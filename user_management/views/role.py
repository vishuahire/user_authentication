from rest_framework.generics import *
from user_management.models.role import *
from user_management.serializers.role import *
from user_management.authentication import JWTAuthentication
from django.db.models import Q
from django.urls import reverse
from rest_framework.exceptions import PermissionDenied,AuthenticationFailed
from user_management.models.exception import ExceptionError
import traceback
import sys
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
import json
from datetime import datetime



class UserRoleListview(ListAPIView):
    """
    get Role list

    Query parameters for GET method
    ---------------------------------------
    1. is_active = true or false
    2. role = string
    3. role_desc = string
    4. id = ID of role
    5. department_id = ID department
        
    eg. http://127.0.0.1:8000/users/get-user-roles/

    return - list of Role
    """
    try:
        # authentication_classes = [JWTAuthentication]
        serializer_class = UserRoleserializer
       
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
            queryset = Role.all_objects.all().order_by('-id')
            is_active = self.request.GET.get('is_active')
            role = self.request.GET.get('role')
            role_desc = self.request.GET.get('role_desc')
            role_id = self.request.GET.get('id')
            # department_id = self.request.GET.get('department_id')

    
            if is_active :   
                is_active = is_active.strip('\n').strip('\t')
                if is_active == 'All' :
                    q_objects.add(Q(),Q.AND)
                else:
                    q_objects.add(Q(is_active=is_active), Q.AND) 
                
            else:
                if role_id:
                    q_objects.add(Q(),Q.AND)
                else:
                    q_objects.add(Q(is_active=True),Q.AND)

            # if department_id:
            #     department_id= department_id.strip('\n').strip('\t').strip()
            #     q_objects.add(Q(department_id=department_id), Q.AND)
            if role : 
                q_objects.add(Q(role__icontains=role), Q.AND)
            if role_desc : 
                q_objects.add(Q(role_desc__icontains=role_desc), Q.AND)
            if role_id : 
                q_objects.add(Q(id=role_id), Q.AND)

            if len(q_objects) > 0 :
                queryset = queryset.filter(q_objects).order_by("-id")    

            return queryset    
    except:
        def generate_error():
            ExceptionError.objects.create(http_status=status.HTTP_403_FORBIDDEN,api_url= None,error_message=sys.exc_info())
            response = {'status': "error",'message':sys.exc_info(),'status_code':status.HTTP_403_FORBIDDEN}
            return Response(response)
        generate_error()


class UserRoleCreate(CreateAPIView):
    """
    create role

    body parameters for POST method
    ---------------------------------------
    1. role = string
    2. role_desc = string
    3. created_by = ID of user
    4. permissions = ID of permission
    5. department = ID of Department

    eg. http://127.0.0.1:8000/users/create-user-role/
   
    return role object.
    """
    try:
        # authentication_classes = [JWTAuthentication]
        serializer_class = UserRoleCreateserializer

        def create(self, request, *args, **kwargs):
            serializer = self.get_serializer(data=request.data)
            role = request.data['role']
            role_desc = request.data['role_desc']
            permissions = request.data['permissions']
            # department = request.data['department']
            if serializer.is_valid():
                if Role.all_objects.filter(role = role,is_active =False).exists():
                    role = Role.all_objects.filter(role = role,is_active =False).order_by('-id')[0]
                    role.is_active =True
                    role.role_desc =role_desc
                    role.department_id =department
                    for per in permissions:
                        role.permissions.add(per)
                    role.save()
                    
                    headers = self.get_success_headers(serializer.data)
                    response = {'status': "success",'message':serializer.data,'status_code':status.HTTP_201_CREATED}
                    return Response(response,headers=headers)
                else:
                    self.perform_create(serializer)
                    headers = self.get_success_headers(serializer.data)
                    response = {'status': "success",'message':serializer.data,'status_code':status.HTTP_201_CREATED}
                    return Response(response, headers=headers)
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



class UserRoleDetailview(UpdateAPIView):
    """
    update role

    parameters for PUT/PATCH  method
    --------------------------------------
    1. id - ID of role

    body parameters for PUT/PATCH method
    ---------------------------------------
    1. is_active = true or false
    2. role = string
    3. role_desc = string
    4. last_modified_by = ID of user
    5. permissions = ID of permission
    6. department = ID of department
  
    eg. http://127.0.0.1:8000/users/update-role/3

    return role object.
    """
    try:
        serializer_class = ManageRoleSerializer
        # authentication_classes = [JWTAuthentication]
        

        def get_queryset(self):
            if self.request.method == "PATCH":
                is_active = json.loads(self.request.body)
                if is_active['is_active'] == True:
                    queryset = Role.all_objects.all().order_by('-id')
                    return queryset
                else:
                    queryset = Role.objects.all().order_by('-id')
                    return queryset
            else:
                queryset = Role.objects.all().order_by('-id')
                return queryset 

    

        def update(self, request, *args, **kwargs):
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            instance.last_modified_date = datetime.now() 
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            if serializer.is_valid():
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



class UserRoleDeleteview(DestroyAPIView):
    """
    delete role
    
    parameters for DELETE method
    --------------------------------------------
    1. id - ID of role

    eg. http://127.0.0.1:8000/users/delete-role/2

    return none.
    """
    serializer_class = ManageRoleSerializer
    # authentication_classes = [JWTAuthentication]
    queryset = Role.all_objects.all().order_by('-id')


