from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from softdelete.models import SoftDeleteModel



class ExceptionError(models.Model):
    created_date = models.DateTimeField(auto_now_add=True)
    http_status = models.CharField(max_length=100,null=True,blank=True)
    api_url = models.CharField(max_length=300,null=True,blank=True)
    method_name = models.CharField(max_length=200,null=True,blank=True)
    line_no = models.CharField(max_length=100,null=True,blank=True)
    file_name = models.CharField(max_length=300,null=True,blank=True)
    error_message = models.TextField(null=True,blank=True)


    class Meta:
        db_table = 'exception_errors'
        default_permissions = ()