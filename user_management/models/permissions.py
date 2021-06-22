from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser
# from django.contrib.auth.models import PermissionsMixin
from softdelete.models import SoftDeleteModel



class Permissions(SoftDeleteModel):
    permission = models.CharField(max_length=100)
    permission_desc = models.CharField(max_length=100)
    created_date = models.DateTimeField(auto_now_add=True)
    # created_by = models.ForeignKey('self',on_delete=models.DO_NOTHING,related_name='permission_created_by')
    created_by = models.IntegerField('self',null=True)
    last_modified_date = models.DateTimeField(null=True, blank=True)
    last_modified_by = models.IntegerField('self', null=True)

    class Meta : 
        db_table = 'permissions'
        ordering = ['pk']
        default_permissions = ()