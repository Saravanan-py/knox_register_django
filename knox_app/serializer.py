from rest_framework import serializers
from .models import *
from django.contrib.auth import authenticate


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['company_name', 'company_mail', 'password', 'category', 'no_of_employees', 'address']


class RegisterUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['company_name', 'company_mail', 'password', 'category', 'no_of_employees', 'address']


class LoginSerializer(serializers.Serializer):
    company_mail = serializers.CharField()
    password = serializers.CharField()


class EmailSerializer(serializers.Serializer):
    company_mail = serializers.CharField()


class OTPSerializer(serializers.Serializer):
    otp = serializers.CharField()


class LicenseSerializer(serializers.Serializer):
    license_key = serializers.CharField()
