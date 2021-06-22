from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser
# from django.contrib.auth.models import PermissionsMixin
from softdelete.models import SoftDeleteModel
from user_management.models.permissions import Permissions

class Role(SoftDeleteModel):
    role = models.CharField(max_length=100, unique=True)
    role_desc = models.CharField(max_length=100,null=True)
    created_date = models.DateTimeField(auto_now_add=True)
    permissions = models.ManyToManyField(Permissions) 
    created_by = models.IntegerField('self',null=True)
    last_modified_date = models.DateTimeField(null=True, blank=True)
    last_modified_by = models.IntegerField('self', null=True)
    
    class Meta : 
        db_table = 'role'
        ordering = ['pk']
        default_permissions = ()


class RolePermissions(models.Model) :
    role = models.ForeignKey(Role, on_delete=models.DO_NOTHING)
    permissions = models.ForeignKey(Permissions, on_delete=models.DO_NOTHING)

    class Meta :
        managed = False
        db_table = 'role_permissions'