from user_management.models.exception import ExceptionError
from rest_framework import serializers
from user_management.models.exception import ExceptionError
from django.db import transaction
from django.utils import timezone


class ExceptionErrorSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExceptionError
        fields = "__all__"