# myapp/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class CustomUserManager(models.Manager):
    def create_user(self, email, password=None, **extra_fields):
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        user = self.create_user(email=email, password=password, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    # Add any other fields you need for your user model

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'

    # Unique related names to resolve clashes
    groups = models.ManyToManyField(Group, through='CustomUserGroup', related_name='custom_user_groups')
    user_permissions = models.ManyToManyField(Permission, through='CustomUserPermission', related_name='custom_user_permissions')

    def __str__(self):
        return self.email

class CustomUserGroup(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, on_delete=models.CASCADE)

class CustomUserPermission(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

class LoginData(models.Model):
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)

    def __str__(self):
        return self.username

class InputData(models.Model):
    input_data = models.BinaryField()
    result = models.FloatField()

    def __str__(self):
        return f"Result: {self.result}"
