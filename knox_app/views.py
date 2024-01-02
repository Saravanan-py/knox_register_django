from django.contrib.auth import authenticate
from django.shortcuts import render
from django.http import HttpResponse
from drf_yasg.utils import swagger_auto_schema
from rest_framework.authtoken.models import Token
from rest_framework.generics import *
from .serializer import *
from .models import *
from rest_framework.response import Response
from django.contrib.auth.hashers import make_password
from rest_framework import permissions, mixins
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, DjangoModelPermissions, AllowAny
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from knox import views as knox_views
from django.contrib.auth import login
from django.core.mail import send_mail
from django.conf import settings
import random
import string
from key_generator.key_generator import generate


def generate_otp():
    return str(random.randint(100000, 999999))


def generate_license_key(length):
    key = generate(seed=101)
    key = key.get_key()
    return key


def send_otp_email(email, otp, license_key):
    subject = 'OTP and License Key for Login'
    message = f'Your OTP is: {otp} and Your license key is: {license_key}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)


# Create your views here.
class Email_API(CreateAPIView):
    serializer_class = EmailSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = EmailSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                otp = generate_otp()
                license = generate_license_key(length=15)
                email = serializer.validated_data['company_mail']
                Verification.objects.create(company_mail=email, otp=otp, license_key=license)
                send_otp_email(email, otp, license)
                data = {
                    'response_code': status.HTTP_201_CREATED,
                    "status": 'SUCCESS',
                    "message": 'User email has been posted successfully',
                    "errorDetails": 'None',
                    "statusFlag": True,
                    "data": serializer.data,
                }
                return Response(data)
            else:
                data = {
                    'response_code': status.HTTP_400_BAD_REQUEST,
                    "status": "FAILED",
                    "message": 'User email is incorrect',
                    "errorDetails": serializer.errors,
                    "statusFlag": False,
                    "data": [],
                }
                return Response(data)
        except Exception as e:
            data = {
                'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                "status": "FAILED",
                "message": 'Sending Process is failed',
                "errorDetails": str(e),
                "statusFlag": False,
                "data": [],
            }
            return Response(data)


class OTPCheck_API(CreateAPIView):
    serializer_class = OTPSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = OTPSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                user_otp = serializer.validated_data['otp']
                otp = Verification.objects.filter(otp=user_otp)
                if otp:
                    data = {
                        'response_code': status.HTTP_201_CREATED,
                        "status": 'SUCCESS',
                        "message": 'OTP is Verified',
                        "errorDetails": 'None',
                        "statusFlag": True,
                        "data": serializer.data,
                    }
                    return Response(data)
                else:
                    data = {
                        'response_code': status.HTTP_400_BAD_REQUEST,
                        "status": "FAILED",
                        "message": 'Check Your OTP',
                        "errorDetails": serializer.errors,
                        "statusFlag": False,
                        "data": [],
                    }
                    return Response(data)
        except Exception as e:
            data = {
                'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                "status": "FAILED",
                "message": 'Process is failed',
                "errorDetails": str(e),
                "statusFlag": False,
                "data": [],
            }
            return Response(data)


class LicenseCheck_API(CreateAPIView):
    serializer_class = LicenseSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer = LicenseSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                license = serializer.validated_data['license_key']
                license_key = Verification.objects.filter(license_key=license)
                if license_key:
                    data = {
                        'response_code': status.HTTP_201_CREATED,
                        "status": 'SUCCESS',
                        "message": 'License is Verified',
                        "errorDetails": 'None',
                        "statusFlag": True,
                        "data": serializer.data,
                    }
                    return Response(data)
                else:
                    data = {
                        'response_code': status.HTTP_400_BAD_REQUEST,
                        "status": "FAILED",
                        "message": 'Check Your License',
                        "errorDetails": serializer.errors,
                        "statusFlag": False,
                        "data": [],
                    }
                    return Response(data)
        except Exception as e:
            data = {
                'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                "status": "FAILED",
                "message": 'Process is failed',
                "errorDetails": str(e),
                "statusFlag": False,
                "data": [],
            }
            return Response(data)


class RegisterUser(CreateAPIView):
    serializer_class = RegisterUserSerializer

    def post(self, request, *args, **kwargs):
        try:
            serializer_class = RegisterUserSerializer(data=request.data)
            hpass = make_password(request.data['password'])
            if serializer_class.is_valid():
                serializer_class.validated_data['id'] = 'VIV' + ''.join(random.choice(string.digits) for _ in range(5))
                serializer_class.validated_data['password'] = hpass
                serializer_class.save()
                data = {
                    'response_code': status.HTTP_201_CREATED,
                    "status": 'SUCCESS',
                    "message": 'User Details Created Successfully',
                    "errorDetails": None,
                    "statusFlag": True,
                    "data": serializer_class.data,
                }
                return Response(data)
            else:
                data = {
                    'response_code': status.HTTP_400_BAD_REQUEST,
                    "status": "FAILED",
                    "message": 'Incorrect Details',
                    "errorDetails": serializer.errors,
                    "statusFlag": False,
                    "data": [],
                }
                return Response(data)
        except Exception as e:
            data = {
                'response_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                "status": "FAILED",
                "message": 'Creating Process is failed',
                "errorDetails": str(e),
                "statusFlag": False,
                "data": [],
            }
            return Response(data)


class LoginAPI(knox_views.LoginView, CreateAPIView):
    permission_classes = (AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, format=None):
        try:
            serializer = LoginSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                email = serializer.data['company_mail']
                password = serializer.data['password']
                user = authenticate(request, company_mail=email, password=password)
                login(request, user)
                response = super().post(request, format=None)
                data = {
                    "response_code": status.HTTP_201_CREATED,
                    "message": 'User Details Created Successfully',
                    "statusFlag": True,
                    "status": "SUCCESS",
                    "errorDetails": 'None',
                    "data": {"token": response.data['token']},
                }
                return Response(data)
            else:
                data = {
                    "response_code": status.HTTP_400_BAD_REQUEST,
                    "message": 'Incorrect Details',
                    "statusFlag": False,
                    "status": 'FAILED',
                    "errorDetails": serializer.errors,
                    "data": [],
                }
                return Response(data)

        except Exception as e:
            data = {
                "response_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "message": 'Login Process is failed',
                "status": "FAILED",
                "errorDetails": str(e),
                "statusFlag": False,
                "data": [],
            }
            return Response(data)
