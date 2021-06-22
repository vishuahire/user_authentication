from rest_framework.generics import *
from user_management.models.user import *
from user_management.serializers.user import *
from django.db.models import Q
from user_management.authentication import JWTAuthentication
from rest_framework.decorators import api_view, APIView, authentication_classes
from django.utils import timezone
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
import traceback
import sys
from django.core.exceptions import ObjectDoesNotExist
from user_authentication.settings import JWT_AUTH
from django.urls import reverse
from rest_framework.exceptions import PermissionDenied, AuthenticationFailed
import jwt, json
from django.contrib.auth.hashers import check_password, make_password
from user_management.models.exception import ExceptionError
from user_management.models.role import Role, RolePermissions
from user_management.models.permissions import Permissions
from django.db.models import Q
from rest_framework import generics
from django.contrib.auth.models import User
import random as r
import datetime

from django.http import JsonResponse
from datetime import datetime, timedelta


class Dictlist(dict):
    def __setitem__(self, key, value):
        try:
            self[key]
        except KeyError:
            super(Dictlist, self).__setitem__(key, [])
        self[key].append(value)


class Authenticationadminpanel(CreateAPIView):
    """
    for authenticate user

    passing parametrer
    --------------------------------------
    1.Authorization - static token i.e. ab2dc22a-ba9d-11ea-b3de-0242ac130004

    body parameters for POST  method
    ---------------------------------------
    1.email - valid email id
    2.password - string

    eg. http://127.0.0.1:8000/users/authenticate/?authrization=ab2dc22a-ba9d-11ea-b3de-0242ac130004

    return - access_token and refresh_token
    """

    serializer_class = AuthenticateSerializer

    def post(self, request):
        try:
            token = self.request.META["HTTP_AUTHORIZATION"]
            print("given")
            if token == "":
                print("\n11111")
                data = {
                    #'api_url':self.request.get_host() + reverse('authenticate'),
                    "error_message": "Authorization key required.",
                    "http_status": status.HTTP_400_BAD_REQUEST,
                }
                response = {
                    "status": "error",
                    "message": data,
                    "status_code": status.HTTP_400_BAD_REQUEST,
                }
                # ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_400_BAD_REQUEST)

            # check given static is valid
            if token == "ab2dc22a-ba9d-11ea-b3de-0242ac130004":
                print("yes")
                try:
                    lists = []
                    query = []
                    permissions_objects = []
                    email = request.data["email"]
                    password = request.data["password"]
                    user = Users.objects.get(user_name=email)
                    user_roles = UsersRole.objects.filter(users_id=user.id).values_list(
                        "role_id"
                    )
                    roles = Role.objects.filter(id__in=user_roles).values("role")
                    per = RolePermissions.objects.filter(role_id__in=user_roles).values(
                        "role_id__role", "permissions_id__permission"
                    )
                    blank_dict = {}
                    blank_list = []
                    des_key = []
                    for per in per:
                        query.append(per)
                        if per["role_id__role"] not in des_key:
                            des_key.append(per["role_id__role"])
                            blank_list.append(
                                {
                                    "roles": per["role_id__role"],
                                    "permission": [per["permissions_id__permission"]],
                                }
                            )
                        else:
                            blank_list[des_key.index(per["role_id__role"])][
                                "permission"
                            ].append(per["permissions_id__permission"])

                    if user:
                        print("fbvhf")
                        print(user.password)
                        check_passwd = check_password(password, user.password)
                        print(check_passwd)
                        if check_passwd:
                            print("fvfv")
                            # try:
                            # payload = jwt_payload_handler(user)
                            access_payload = {
                                "token_type": "access",
                                "first_name": user.first_name,
                                "email": user.user_name,
                                "last_name": user.last_name,
                                "id": user.id,
                                "department_id": user.department.id,
                                # 'role':[query[i]['role'] for i in range (len(query))],
                                "role": blank_list,
                                # 'permissions':[permissions_objects[i]['permission'] for i in range (len(permissions_objects))],
                                "exp": timezone.now()
                                - timedelta(days=0.2291)
                                + JWT_AUTH["JWT_EXPIRATION_DELTA"],
                            }

                            refresh_payload = {
                                "token_type": "refresh",
                                "first_name": user.first_name,
                                "email": user.user_name,
                                "last_name": user.last_name,
                                "id": user.id,
                                "role": blank_list,
                                # 'role':[query[i]['role'] for i in range (len(query))],
                                # 'permissions':[permissions_objects[i]['permission'] for i in range (len(permissions_objects))],
                                "exp": timezone.now()
                                - timedelta(days=0.2291)
                                + JWT_AUTH["JWT_REFRESH_EXPIRATION_DELTA"],
                            }
                            user.last_login = timezone.now()
                            user.save()
                            access_token = jwt.encode(
                                access_payload, settings.SECRET_KEY
                            )
                            refresh_token = jwt.encode(
                                refresh_payload, settings.SECRET_KEY
                            )
                            UserActiveLoggedIn.objects.create(
                                user_id=user.id,
                                created_date=timezone.now(),
                                token=access_token,
                            )
                            UserLoggedIn.objects.create(
                                user=user, log_date=timezone.now()
                            )
                            user_details = {}
                            user_details["access_token"] = access_token
                            user_details["refresh_token"] = refresh_token
                            response = [
                                {
                                    "status": "success",
                                    "message": user_details,
                                    "status_code": status.HTTP_200_OK,
                                }
                            ]
                            return Response(response)
                        else:
                            data = {
                                #'api_url':self.request.get_host() + reverse('authenticate'),
                                "error_message": ["Invalid login credentials."],
                                #'http_status':status.HTTP_401_UNAUTHORIZED
                            }
                            response = {
                                "status": "error",
                                "message": data,
                                "status_code": status.HTTP_401_UNAUTHORIZED,
                            }
                            ExceptionError.objects.create(**data)
                            return Response(
                                response, status=status.HTTP_401_UNAUTHORIZED
                            )

                    else:
                        data = {
                            #'api_url':self.request.get_host() + reverse('authenticate'),
                            "error_message": ["Invalid login credentials."],
                            #'http_status':status.HTTP_401_UNAUTHORIZED
                        }
                        response = {
                            "status": "error",
                            "message": data,
                            "status_code": status.HTTP_401_UNAUTHORIZED,
                        }
                        ExceptionError.objects.create(**data)
                        return Response(response, status=status.HTTP_401_UNAUTHORIZED)

                except ObjectDoesNotExist:
                    data = {
                        #'api_url':self.request.get_host() + reverse('authenticate'),
                        "error_message": ["User does not exist."],
                        #'http_status':status.HTTP_401_UNAUTHORIZED
                    }
                    response = {
                        "status": "error",
                        "message": data,
                        "status_code": status.HTTP_401_UNAUTHORIZED,
                    }
                    ExceptionError.objects.create(**data)
                    return Response(response, status=status.HTTP_401_UNAUTHORIZED)

            else:
                response = {
                    "status": "error",
                    "message": PermissionDenied(),
                    "status_code": status.HTTP_401_UNAUTHORIZED,
                }
                raise PermissionDenied(response)
        except KeyError:
            data = {
                #'api_url':self.request.get_host() + reverse('authenticate'),
                "error_message": ["Invalid login credentials."],
                #'http_status':status.HTTP_401_UNAUTHORIZED
            }
            response = {
                "status": "error",
                "message": data,
                "status_code": status.HTTP_400_BAD_REQUEST,
            }
            ExceptionError.objects.create(**data)
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


class GetUserView(ListAPIView):
    """
    get User list

    Query parameters for GET method
    ---------------------------------------
    1. email - valid email address
    2. is_active - true or false
    3. id - ID of user
    4. roles = ID of roles
    5. department_id = ID of department

    eg. http://127.0.0.1:8000/users/get/

    return - list of users
    """

    authentication_classes = [JWTAuthentication]
    serializer_class = UserviewSerializer

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        response = {
            "status": "success",
            "message": serializer.data,
            "status_code": status.HTTP_200_OK,
        }
        return Response(response)

    def get_queryset(self):
        q_objects = Q()
        queryset = Users.all_objects.all().order_by("-id")
        email = self.request.GET.get("email")
        is_active = self.request.GET.get("is_active")
        user_id = self.request.GET.get("id")
        roles = self.request.GET.get("roles")
        # department_id = self.request.GET.get("department_id")

        if user_id:
            user_id = user_id.strip("\n").strip("\t")
            q_objects.add(Q(id = user_id),Q.AND)

        if email:
            email = email.strip("\n").strip("\t")
            q_objects.add(Q(user_name__icontains=email), Q.AND)

        if is_active:
            is_active = is_active.strip("\n").strip("\t")
            if is_active == "All":
                q_objects.add(Q(), Q.AND)
            else:
                q_objects.add(Q(is_active=is_active), Q.AND)
        else:
            if user_id:
                q_objects.add(Q(), Q.AND)
            else:
                q_objects.add(Q(is_active=True), Q.AND)

        # if department_id:
        #     department_id = department_id.strip("\n").strip("\t")
        #     q_objects.add(Q(department_id=department_id), Q.AND)

        if roles:
            roles = [ int(x) for x in roles.split(',') ]
            q_objects.add(Q(roles__in=roles), Q.AND)
            

        if len(q_objects) > 0:
            queryset = queryset.filter(q_objects).order_by("-id")

        return queryset


class PostUser(CreateAPIView):
    """
    create user

    body parameters for POST method
    ---------------------------------------
    1. first_name = string
    2. last_name = string
    3. user_name = email address
    4. roles = ID of roles
    5. password = string
    6. is_active = true or false
    7. created_by = ID of user
    8. department = ID of department
    9. mobile_no = 10 digit Integer number

    eg. http://127.0.0.1:8000/users/add/

    return user object.
    """

    # authentication_classes = [JWTAuthentication]
    serializer_class = GetPostRequestUserSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Checks if the data recieved from the user is valid
            # if data is valid, returns 200
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            response = {
                "status": "success",
                "message": serializer.data,
                "status_code": status.HTTP_201_CREATED,
            }
            return Response(response, headers=headers)
        else:
            data = {
                "api_url": self.request.get_host() + reverse("authenticate"),
                "error_message": serializer.errors,
                "http_status": status.HTTP_400_BAD_REQUEST,
            }
            # if data is invalid, returns error message along with status code
            response = {
                "status": "error",
                "message": serializer.errors,
                "status_code": status.HTTP_400_BAD_REQUEST,
            }
            ExceptionError.objects.create(**data)
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


class UserUpdateView(UpdateAPIView):
    """
    update user

    parameters for PUT/PATCH  method
    ----------------------------------
    1. id - ID of user

    body parameters for PUT/PATCH method
    ---------------------------------------
    1. id_active = true or false
    2. first_name = string
    3. last_name = string
    4. roles = ID of roles
    5. last_modify_by = ID of user
    6. department_id =  ID of deparment

    eg. http://127.0.0.1:8000/users/update-user/1

    return user object.
    """

    serializer_class = UpdateUserSerializer
    # authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        if self.request.method == "PATCH":
            is_active = json.loads(self.request.body)
            if is_active["is_active"] == True:
                queryset = Users.all_objects.all().order_by("-id")
                return queryset
            else:
                queryset = Users.objects.all().order_by("-id")
                return queryset
        else:
            queryset = Users.objects.all().order_by("-id")
            return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        instance.last_modified_date = datetime.now()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        if serializer.is_valid():
            self.perform_update(serializer)

            if getattr(instance, "_prefetched_objects_cache", None):
                # If 'prefetch_related' has been applied to a queryset, we need to
                # forcibly invalidate the prefetch cache on the instance.
                instance._prefetched_objects_cache = {}
            response = {
                "status": "success",
                "message": serializer.data,
                "status_code": status.HTTP_200_OK,
            }
            return Response(response)
        else:
            data = {
                "api_url": self.request.get_host(),
                "error_message": serializer.errors,
                "http_status": status.HTTP_400_BAD_REQUEST,
            }
            response = {
                "status": "error",
                "message": serializer.errors,
                "status_code": status.HTTP_400_BAD_REQUEST,
            }
            ExceptionError.objects.create(**data)
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

    def perform_update(self, serializer):
        serializer.save()

    def partial_update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)


class UserDeleteView(DestroyAPIView):
    """
    delete user

    parameters for DELETE method
    --------------------------------------
    1. id - ID of user

    eg. http://127.0.0.1:8000/users/delete-user/2

    return none.
    """

    # authentication_classes = [JWTAuthentication]
    serializer_class = UserviewSerializer
    queryset = Users.objects.all().order_by("-id")

    # Overide delete()
    def delete(self, request, *args, **kwargs):
        user = self.get_object()
        ticket_count = Ticket.objects.filter(
            assign_to=user.id, ticket_status="Open"
        ).count()
        token_obj = UserActiveLoggedIn.objects.filter(user_id=user.id)
        if ticket_count > 0:
            e_message = {"Ticket existed againest this user."}
            data = {
                "api_url": self.request.get_host() + reverse("authenticate"),
                "error_message": {"error_message": e_message},
                "http_status": status.HTTP_400_BAD_REQUEST,
            }
            response = {
                "status": "error",
                "message": {"error_message": e_message},
                "status_code": status.HTTP_401_UNAUTHORIZED,
            }
            ExceptionError.objects.create(**data)
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

        user.is_active = False
        token_obj.delete()
        user.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class TokenBaseView(GenericAPIView):
    authentication_classes = []
    permission_classes = []
    serializer_class = None

    www_authenticate_realm = "api"

    def get_authenticate_header(self, request):
        return '{0} realm="{1}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


class ChangePasswordView(UpdateAPIView):
    """
    change the password

    body parameters for PUT  method
    ---------------------------------------
    1. old_password - string
    2. new_password - string

    eg. http://127.0.0.1:8000/users/change-password/

    return - new password is set.
    """

    try:
        serializer_class = ChangePasswordSerializer
        model = Users
        authentication_classes = [JWTAuthentication]

        def get_object(self, queryset=None):
            obj = self.request.user
            return obj

        def update(self, request, *args, **kwargs):
            user = self.get_object()
            serializer = self.get_serializer(data=request.data)
            old_password = request.data["old_password"].strip("\n").strip("\t").strip()
            new_password = request.data["new_password"].strip("\n").strip("\t").strip()

            # check old_password is blank
            if old_password == "":
                e_message = {"old password is required."}
                data = {
                    "api_url": self.request.get_host() + reverse("authenticate"),
                    "error_message": {"old_password": e_message},
                    "http_status": status.HTTP_401_UNAUTHORIZED,
                }
                response = {
                    "status": "error",
                    "message": {"old_password": e_message},
                    "status_code": status.HTTP_401_UNAUTHORIZED,
                }
                ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_401_UNAUTHORIZED)

            # check new_password is blank
            if new_password == "":
                e_message = {"new password is required."}
                data = {
                    "api_url": self.request.get_host() + reverse("authenticate"),
                    "error_message": {"new_password": e_message},
                    "http_status": status.HTTP_401_UNAUTHORIZED,
                }
                response = {
                    "status": "error",
                    "message": {"new_password": e_message},
                    "status_code": status.HTTP_401_UNAUTHORIZED,
                }
                ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_401_UNAUTHORIZED)

            # check if new_password contains space
            if " " in new_password:
                e_message = {"New Password space not allowed."}
                data = {
                    "api_url": self.request.get_host() + reverse("authenticate"),
                    "error_message": {"new_password": e_message},
                    "http_status": status.HTTP_401_UNAUTHORIZED,
                }
                response = {
                    "status": "error",
                    "message": {"new_password": e_message},
                    "status_code": status.HTTP_401_UNAUTHORIZED,
                }
                ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_401_UNAUTHORIZED)

            if serializer.is_valid():
                # Check old password is valid
                if not check_password(old_password, user.password):
                    e_message = {"Wrong password."}
                    data = {
                        "api_url": self.request.get_host() + reverse("authenticate"),
                        "error_message": {"old_password": e_message},
                        "http_status": status.HTTP_401_UNAUTHORIZED,
                    }
                    response = {
                        "status": "error",
                        "message": {"old_password": e_message},
                        "status_code": status.HTTP_401_UNAUTHORIZED,
                    }
                    ExceptionError.objects.create(**data)
                    return Response(response, status=status.HTTP_401_UNAUTHORIZED)

                # set_password also hashes the password that the user will get
                user.password = serializer.data.get("new_password")
                user.save(update_fields=["password"])
                response = {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": {"Password updated successfully"},
                    "data": [],
                }

                return Response(response)
            else:
                # if data is invalid, returns error message along with status code
                response = {
                    "status": "error",
                    "message": serializer.errors,
                    "status_code": status.HTTP_400_BAD_REQUEST,
                }
                return Response(response)

    except:

        def generate_error():
            ExceptionError.objects.create(
                http_status=status.HTTP_403_FORBIDDEN,
                api_url=None,
                error_message=sys.exc_info(),
            )
            response = {
                "status": "error",
                "message": sys.exc_info(),
                "status_code": status.HTTP_403_FORBIDDEN,
            }
            return Response(response)

        generate_error()


class ForgotPasswordView(CreateAPIView):
    """
    Forget password request

    body parameters for POST  method
    ---------------------------------------
    1. email_address - valid email address

    eg. http://127.0.0.1:8000/users/forgot-password/

    return - send otp sms in your register mobile number
    """

    try:

        authentication_classes = []

        serializer_class = ForgetPasswordSerializer

        def post(self, request, *args, **kwargs):

            # get email address
            email_address = request.data["email_address"]

            # check email address is valid
            if email_address:
                email_address = email_address.strip("\n").strip("\t").strip()

            # check email_address is blank
            elif email_address == "":
                e_message = {"Email address is required."}
                data = {
                    "api_url": self.request.get_host() + reverse("authenticate"),
                    "error_message": {"email_address": e_message},
                    "http_status": status.HTTP_400_BAD_REQUEST,
                }
                response = {
                    "status": "error",
                    "message": {"email_address": e_message},
                    "status_code": status.HTTP_401_UNAUTHORIZED,
                }
                ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_401_UNAUTHORIZED)

            # check given email_address is register email_address
            if Users.objects.filter(user_name=email_address).exists():
                # get user object
                user = Users.objects.get(user_name=email_address)
                user_id = user.id

                # call otp template for send otp sms for register mobile number
                otpTemplate(user_id)

                response = {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": {"OTP sent."},
                    "data": [],
                }

                return Response(response)

            else:
                e_message = {"Email address does not exist."}
                data = {
                    "api_url": self.request.get_host() + reverse("authenticate"),
                    "error_message": {"email_address": e_message},
                    "http_status": status.HTTP_401_UNAUTHORIZED,
                }
                response = {
                    "status": "error",
                    "message": {"email_address": e_message},
                    "status_code": status.HTTP_401_UNAUTHORIZED,
                }
                ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_401_UNAUTHORIZED)

    except:

        def generate_error():
            ExceptionError.objects.create(
                http_status=status.HTTP_401_UNAUTHORIZED,
                api_url=None,
                error_message=sys.exc_info(),
            )
            response = {
                "status": "error",
                "message": sys.exc_info(),
                "status_code": status.HTTP_401_UNAUTHORIZED,
            }
            return Response(response)

        generate_error()


class ForgotPasswordOtpView(CreateAPIView):
    """
    forgot password reset

    body parameters for POST  method
    ---------------------------------------
    1. email_address - valid email address
    2. otp - 6 digit Intger number
    3. password - string

    eg. http://127.0.0.1:8000/users/update-password-otp/

    return- reset password
    """

    try:

        authentication_classes = []

        serializer_class = ForgetPasswordotpSerializer

        def post(self, request, *args, **kwargs):
            email_address = request.data["email_address"]
            otp = request.data["otp"]
            password = request.data["password"]

            # check given email address is register email address
            if Users.objects.filter(user_name=email_address).exists():
                user = Users.objects.get(user_name=email_address)
                user_id = user.id

                # check given otp is valid otp
                if OTP.objects.filter(otp=otp).exists():
                    otp = OTP.objects.get(otp=otp)
                    timestamp = otp.expiry_timestamp
                    current_date = datetime.now()

                    # check given otp is valid ie. given otp is not expired.
                    if current_date <= timestamp:
                        user.password = password
                        user.save(update_fields=["password"])
                        otp.delete()
                        response = {
                            "status": "success",
                            "code": status.HTTP_200_OK,
                            "message": {"Password is Reset successfully"},
                            "data": [],
                        }
                        return Response(response)
                    else:
                        e_message = {"OTP is Expired."}
                        data = {
                            "api_url": self.request.get_host()
                            + reverse("authenticate"),
                            "error_message": {"otp": e_message},
                            "http_status": status.HTTP_401_UNAUTHORIZED,
                        }
                        response = {
                            "status": "error",
                            "message": {"otp": e_message},
                            "status_code": status.HTTP_401_UNAUTHORIZED,
                        }
                        ExceptionError.objects.create(**data)
                        return Response(response, status=status.HTTP_401_UNAUTHORIZED)
                else:
                    e_message = {"Invalid OTP."}
                    data = {
                        "api_url": self.request.get_host() + reverse("authenticate"),
                        "error_message": {"otp": e_message},
                        "http_status": status.HTTP_401_UNAUTHORIZED,
                    }
                    response = {
                        "status": "error",
                        "message": {"otp": e_message},
                        "status_code": status.HTTP_401_UNAUTHORIZED,
                    }
                    ExceptionError.objects.create(**data)
                    return Response(response, status=status.HTTP_401_UNAUTHORIZED)

            else:
                e_message = {"Invalid email address."}
                data = {
                    "api_url": self.request.get_host() + reverse("authenticate"),
                    "error_message": {"email_address": e_message},
                    "http_status": status.HTTP_401_UNAUTHORIZED,
                }
                response = {
                    "status": "error",
                    "message": {"email_address": e_message},
                    "status_code": status.HTTP_401_UNAUTHORIZED,
                }
                ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_401_UNAUTHORIZED)

    except:

        def generate_error():
            ExceptionError.objects.create(
                http_status=status.HTTP_403_FORBIDDEN,
                api_url=None,
                error_message=sys.exc_info(),
            )
            response = {
                "status": "error",
                "message": sys.exc_info(),
                "status_code": status.HTTP_403_FORBIDDEN,
            }
            return Response(response)

        generate_error()


class ResntOTPView(CreateAPIView):
    """
    resend otp request

    body parameters for POST  method
    ---------------------------------------
    1. email_address - valid email address

    eg.

    return - send otp sms in your register mobile number
    """

    try:

        authentication_classes = []

        serializer_class = ForgetPasswordSerializer

        def post(self, request, *args, **kwargs):

            # get email address
            email_address = request.data["email_address"]

            # check email address is valid
            if email_address:
                email_address = email_address.strip("\n").strip("\t").strip()

            # check email_address is blank
            elif email_address == "":
                e_message = {"Email address is required."}
                data = {
                    "api_url": self.request.get_host() + reverse("authenticate"),
                    "error_message": {"email_address": e_message},
                    "http_status": status.HTTP_400_BAD_REQUEST,
                }
                response = {
                    "status": "error",
                    "message": {"email_address": e_message},
                    "status_code": status.HTTP_401_UNAUTHORIZED,
                }
                ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_401_UNAUTHORIZED)

            # check given email_address is register email_address
            if Users.objects.filter(user_name=email_address).exists():
                # get user object
                user = Users.objects.get(user_name=email_address)
                user_id = user.id

                # call otp template for send otp sms for register mobile number
                resendOtpTemplate(user_id)

                response = {
                    "status": "success",
                    "code": status.HTTP_200_OK,
                    "message": {"OTP sent."},
                    "data": [],
                }

                return Response(response)

            else:
                e_message = {"Email address does not exist."}
                data = {
                    "api_url": self.request.get_host() + reverse("authenticate"),
                    "error_message": {"email_address": e_message},
                    "http_status": status.HTTP_401_UNAUTHORIZED,
                }
                response = {
                    "status": "error",
                    "message": {"email_address": e_message},
                    "status_code": status.HTTP_401_UNAUTHORIZED,
                }
                ExceptionError.objects.create(**data)
                return Response(response, status=status.HTTP_401_UNAUTHORIZED)

    except:

        def generate_error():
            ExceptionError.objects.create(
                http_status=status.HTTP_401_UNAUTHORIZED,
                api_url=None,
                error_message=sys.exc_info(),
            )
            response = {
                "status": "error",
                "message": sys.exc_info(),
                "status_code": status.HTTP_401_UNAUTHORIZED,
            }
            return Response(response)

        generate_error()
