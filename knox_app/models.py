from django.db import models
from django.contrib.auth.models import AbstractBaseUser, AbstractUser, PermissionsMixin
from knox_app.managers import CustomUserManager
import random
import string
from django.contrib.auth.models import Group, Permission


# Create your models here.
class CustomUser(AbstractBaseUser, PermissionsMixin):
    CATEGORY_CHOICES = (
        ("INSURANCE", "Insurance"),
        ("HR", "HR"),
        ("HOSPITALS", "Hospitals")
    )
    EMPLOYEE_CHOICES = (
        ("Below_100", "Below_100"),
        ("Below_200", "Below_200"),
        ("Below_300", "Below_300")
    )

    id = models.CharField(primary_key=True, max_length=8, unique=True)
    company_mail = models.EmailField(max_length=50, unique=True)
    company_name = models.CharField(max_length=100, unique=True, default=True)
    password = models.CharField(max_length=100, null=True)
    category = models.CharField(choices=CATEGORY_CHOICES, max_length=30, null=True)
    no_of_employees = models.CharField(choices=EMPLOYEE_CHOICES, max_length=10, null=True)
    address = models.CharField(max_length=100, null=True)
    created_at = models.DateTimeField(auto_now=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = 'company_mail'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.company_mail


class Verification(models.Model):
    company_mail = models.CharField(primary_key=True, max_length=100)
    otp = models.IntegerField()
    license_key = models.CharField(max_length=200)
