from django.urls import path, include

from user_management.views import exception, role, permissions, user


urlpatterns = [
    path('exception-errors/',exception.ExceptionErrrosView.as_view(),name='exception-errors'),
    path('create-user-role/',role.UserRoleCreate.as_view(),name='create-user-role'),
    path('get-user-roles/',role.UserRoleListview.as_view(),name='get-user-roles'),
    path('update-role/<int:pk>',role.UserRoleDetailview.as_view(),name='manage-role'),
    path('delete-role/<int:pk>',role.UserRoleDeleteview.as_view()),
    path('authenticate/', user.Authenticationadminpanel.as_view(),name='authenticate'),
    path('get/', user.GetUserView.as_view()),
    path('add/', user.PostUser.as_view()),
    path('update-user/<int:pk>', user.UserUpdateView.as_view()), 
    path('delete-user/<int:pk>',user.UserDeleteView.as_view()),  
    path('get-user-permission/',permissions.UserPermission.as_view()),
    path('create-permission/',permissions.UserCreatePermission.as_view()),
    path('update-permission/<int:pk>',permissions.UpdatePermission.as_view()),
    path('delete-permission/<int:pk>',permissions.DeletePermission.as_view()),
    path('change-password/',user.ChangePasswordView.as_view()),
    path('forgot-password/',user.ForgotPasswordView.as_view()),
    path('update-password-otp/',user.ForgotPasswordOtpView.as_view()),
    path('resend-otp/',user.ResntOTPView.as_view()),
]