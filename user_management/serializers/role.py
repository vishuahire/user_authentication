from django.db import transaction
from django.utils import timezone
from user_management.models.role import Role
from rest_framework import serializers
from .permissions import UserPermissionserializer
from user_management.models.role import RolePermissions



class UserRoleserializer(serializers.ModelSerializer):
    
    permissions = serializers.SerializerMethodField()
    class Meta:
        model = Role
        fields = ['id','is_active','role','role_desc','created_date','created_by','last_modified_date','last_modified_by','permissions']

    def get_permissions(self, instance):
        permissions = instance.permissions.all().order_by('-id')
        return UserPermissionserializer(permissions, many=True).data


class UserRoleCreateserializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ['id','is_active','role','role_desc','permissions','created_date','created_by','last_modified_date']
        read_only_fields = ['id','created_date','last_modified_date']


class ManageRoleSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Role
        fields = ['id','is_active','role','role_desc','permissions','last_modified_by','created_date','created_by','last_modified_date']
        read_only_fields = ['id','created_date','created_by','last_modified_date','created_date','created_by']

