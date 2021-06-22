from django.db import models
from django.contrib.auth.base_user import AbstractBaseUser
# from django.contrib.auth.models import PermissionsMixin
from softdelete.models import SoftDeleteModel
from user_management.models.role import Role
from django.contrib.auth.hashers import make_password
from user_authentication.validators import validate_mobile_no

class Users(SoftDeleteModel):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    password = models.CharField(max_length=150)
    last_login = models.DateTimeField(null=True,blank=True)
    user_name = models.EmailField()
    department = models.CharField(max_length=100, unique=True)
    # role = models.ForeignKey(UserType,on_delete=models.DO_NOTHING)
    created_date = models.DateTimeField(auto_now_add=True)
    roles = models.ManyToManyField(Role)
    last_modified_date = models.DateTimeField(null=True, blank=True)
    last_modified_by = models.IntegerField('self', null=True)
    created_by = models.IntegerField('self',null=True)
    mobile_no = models.CharField(max_length=10,validators=[validate_mobile_no])


    def save(self, *args, **kwargs):
        if not Users.objects.filter(password=self.password).exists():
            self.password = make_password(self.password)
        super(Users, self).save(*args,**kwargs)


    class Meta : 
        db_table = 'user'
        default_permissions = ()


class UserActiveLoggedIn(models.Model) :
    user = models.ForeignKey(Users, on_delete=models.DO_NOTHING)
    created_date = models.DateTimeField()
    token = models.CharField(max_length=5000)

    class Meta :
        db_table = 'user_active_logged_in' 
        default_permissions = ()



class UsersRole(models.Model) :
    users = models.ForeignKey(Users, on_delete=models.DO_NOTHING)
    role = models.ForeignKey(Role, on_delete=models.DO_NOTHING)

    class Meta :
        managed = False
        db_table = 'user_roles'


class UserLoggedIn(models.Model) :
    user = models.ForeignKey(Users, on_delete=models.DO_NOTHING)
    log_date = models.DateTimeField()

    class Meta :
        db_table = 'user_logged_in' 
        default_permissions = ()

class OTP(models.Model):
    otp = models.IntegerField()
    expiry_timestamp = models.DateTimeField()
    mobile_no = models.CharField(max_length=10,validators=[validate_mobile_no])
    email_address = models.EmailField()

    class Meta :
        db_table = 'otp' 
        default_permissions = ()