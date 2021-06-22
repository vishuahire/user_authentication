from django.db import transaction
from django.utils import timezone
from user_management.models.user import Users
from rest_framework import serializers
from user_management.serializers.role import UserRoleserializer
from rest_framework.exceptions import ValidationError, NotFound
from django.utils.translation import gettext as _
from rest_framework import status
from rest_framework.response import Response
from user_management.models.user import UsersRole
from .role import UserRoleserializer


class RoleNameSerializer(serializers.ModelSerializer):
    role = UserRoleserializer()
    class Meta:
        model = UsersRole
        fields = ['role']


class UserviewSerializer(serializers.ModelSerializer):
    # usersrole_set = RoleNameSerializer(many=True)
    # usersrole_set = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()
    
    class Meta:
        model = Users
        fields = ['id','first_name','is_active','last_name','last_login','user_name','created_date','roles','last_modified_date','department','mobile_no']
        read_only_fields = ['last_modified_date']

    def get_roles(self, instance):
        roles = instance.roles.all().order_by('-id')
        return UserRoleserializer(roles, many=True).data


class GetPostRequestUserSerializer(serializers.ModelSerializer):
   
    mobile_no = serializers.CharField(min_length=10)
    def validate_mobile_no(self, value) :
        if value == "" :
            return None
        
        if Users.objects.filter(mobile_no = value).exists() :
            raise ValidationError(_('User with this mobile number already exists.'), code='not_unique')

        return value

    class Meta:
        model = Users
        fields = ['id','first_name', 'last_name', 'user_name', 'roles','password', 'created_date', 'is_active','created_by','department','mobile_no','last_modified_date']
        read_only_fields = ['id','created_date','last_modified_date']

    
    def validate_user_name(self, user_name) :
        user = Users.objects.filter(user_name=user_name) 
        if user.exists() :
            raise ValidationError(_('User with this email already exist.'),code='not_unique')
        return user_name


class UpdateUserSerializer(serializers.ModelSerializer):
   
    # mobile_no = serializers.CharField(min_length=10)
    # def validate_mobile_no(self, value) :
    #     if value == "" :
    #         return None
        
    #     if Users.objects.filter(mobile_no = value).exists() :
    #         raise ValidationError(_('User with this mobile number already exists.'), code='not_unique')

    #     return value
    class Meta:
        model = Users
        fields = ['id', 'is_active', 'first_name', 'last_name', 'user_name', 'roles', 'last_modified_by','created_date','created_by','last_modified_date','department','mobile_no']
        read_only_fields = ['id','created_date','created_by','last_modified_date','user_name','mobile_no']



class AuthenticateSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(max_length=15)


class ChangePasswordSerializer(serializers.Serializer):
    model = Users

    """
    Serializer for password change endpoint.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

class ForgetPasswordSerializer(serializers.Serializer):
    model = Users

    email_address = serializers.EmailField()


class ForgetPasswordotpSerializer(serializers.Serializer):
    email_address  = serializers.EmailField()
    password = serializers.CharField()
    otp = serializers.CharField()