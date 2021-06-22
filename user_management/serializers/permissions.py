from rest_framework import serializers
from user_management.models.permissions import Permissions
from django.db import transaction
from django.utils import timezone



class UserPermissionserializer(serializers.ModelSerializer):
    class Meta:
        model = Permissions
        fields = "__all__"

    


class UserCreatePermissionserializer(serializers.ModelSerializer):
    class Meta:
        model = Permissions
        fields = ['id','is_active','permission','permission_desc','created_by','created_date','last_modified_date']
        read_only_fields = ['id','is_active','created_date','last_modified_date']

    # @transaction.atomic
    # def create(self,validated_data) :
    #     permissions = Permissions(**validated_data) 
    #     permissions.created_by = self.context['request'].auth['id']
    #     permissions.save()
    #     return permissions



class UserUpdatePermissionserializer(serializers.ModelSerializer):
    class Meta:
        model = Permissions
        fields = ['id','is_active','permission','permission_desc','last_modified_by','created_date','created_by','last_modified_date']
        read_only_fields = ['id','created_date','created_by','last_modified_date']

    # @transaction.atomic
    # def update(self, permissions, validated_data) :
    #     ps_update_fields = []
    #     for key, value in validated_data.items() :
    #         if getattr(permissions, key) != value :
    #             ps_update_fields.append(key)
    #             setattr(permissions, key, value)
    #     # permissions.last_modified_by = self.context['request'].auth['id']
    #     permissions.last_modified_date = timezone.now()
    #     ps_update_fields = ps_update_fields + ['last_modified_date']
    #     permissions.save(update_fields = ps_update_fields)
    #     return permissions


        
