# accounts/models.py
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext_lazy as _

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_('The Email field must be set'))
        if not username:
            raise ValueError(_('The Username field must be set'))
        
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self.create_user(username, email, password, **extra_fields)

class CustomUser(AbstractUser):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    
    # Basic fields
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    
    # FIXED: Add missing fields referenced in ProfileSerializer
    profile_photo = models.ImageField(
        upload_to='profile_photos/', 
        null=True, 
        blank=True
    )
    bio = models.TextField(max_length=500, blank=True, default='')
    phone_number = models.CharField(max_length=15, blank=True, null=True)  # FIXED: Added
    date_of_birth = models.DateField(null=True, blank=True)  # FIXED: Added
    location = models.CharField(max_length=100, blank=True)  # FIXED: Added
    
    # Optional fields
    is_private = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        full_name = f"{self.first_name} {self.last_name}".strip()
        return full_name if full_name else self.email

    @property
    def full_name(self):
        """Return full name if available, otherwise username"""
        full_name = f"{self.first_name} {self.last_name}".strip()
        return full_name if full_name else self.username

    def get_age(self):
        """Calculate age from date of birth"""
        if self.date_of_birth:
            from datetime import date
            today = date.today()
            return today.year - self.date_of_birth.year - (
                (today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day)
            )
        return None

    def clean(self):
        super().clean()
        from django.core.exceptions import ValidationError
        if self.email and CustomUser.objects.filter(email__iexact=self.email).exclude(id=self.id).exists():
            raise ValidationError({'email': 'This email is already registered.'})
        if self.username and CustomUser.objects.filter(username__iexact=self.username).exclude(id=self.id).exists():
            raise ValidationError({'username': 'This username is already taken.'})