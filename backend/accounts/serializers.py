# accounts/serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import CustomUser
from rest_framework_simplejwt.tokens import RefreshToken
import re
import logging

logger = logging.getLogger(__name__)

class LoginSerializer(serializers.Serializer):
    """Serializer for login authentication"""
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate_email(self, value):
        """Normalize email"""
        return value.lower().strip()

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            # Try to authenticate with email
            user = authenticate(
                request=self.context.get('request'),
                username=email,
                password=password
            )
            
            # If standard auth fails, try manual email lookup
            if not user:
                try:
                    user = CustomUser.objects.get(email__iexact=email)
                    if user.check_password(password):
                        # Password is correct
                        pass
                    else:
                        raise serializers.ValidationError(
                            'Invalid email or password.'
                        )
                except CustomUser.DoesNotExist:
                    raise serializers.ValidationError(
                        'Invalid email or password.'
                    )
            
            if not user:
                raise serializers.ValidationError(
                    'Invalid email or password.'
                )
                
            if not user.is_active:
                raise serializers.ValidationError(
                    'User account is disabled.'
                )
            
            # FIXED: Generate tokens here in the serializer
            refresh = RefreshToken.for_user(user)
            
            # Return user data and tokens
            attrs['user'] = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name or '',
                'last_name': user.last_name or '',
                'full_name': f"{user.first_name} {user.last_name}".strip() or user.username,
                'bio': user.bio or '',
                'profile_photo': user.profile_photo.url if user.profile_photo else None,
                'is_private': getattr(user, 'is_private', False),
                'email_verified': getattr(user, 'email_verified', False),
                'phone_verified': getattr(user, 'phone_verified', False),
                'date_joined': user.date_joined.isoformat() if user.date_joined else None
            }
            
            # FIXED: Add tokens to attrs
            attrs['access'] = str(refresh.access_token)
            attrs['refresh'] = str(refresh)
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            return attrs
        else:
            raise serializers.ValidationError(
                'Must include email and password.'
            )

class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, min_length=8)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'password', 'password2'
        ]
        extra_kwargs = {
            'username': {'required': True, 'min_length': 3},
            'email': {'required': True},
            'first_name': {'required': False, 'max_length': 30},
            'last_name': {'required': False, 'max_length': 30},
        }

    def validate_email(self, value):
        if CustomUser.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value.lower().strip()

    def validate_username(self, value):
        if CustomUser.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError("A user with this username already exists.")
        # FIXED: More lenient username validation
        if not re.match(r'^[a-zA-Z0-9_.@+-]+$', value):
            raise serializers.ValidationError("Username can only contain letters, numbers, dots, underscores, at signs, plus signs, and hyphens.")
        if len(value) < 3:
            raise serializers.ValidationError("Username must be at least 3 characters long.")
        return value.strip()

    def validate_first_name(self, value):
        """Validate first name format"""
        if value:
            value = value.strip()
            if len(value) > 30:
                raise serializers.ValidationError("First name cannot exceed 30 characters.")
            if not re.match(r'^[a-zA-Z\s\-\']+$', value):
                raise serializers.ValidationError("First name can only contain letters, spaces, hyphens, and apostrophes.")
        return value

    def validate_last_name(self, value):
        """Validate last name format"""
        if value:
            value = value.strip()
            if len(value) > 30:
                raise serializers.ValidationError("Last name cannot exceed 30 characters.")
            if not re.match(r'^[a-zA-Z\s\-\']+$', value):
                raise serializers.ValidationError("Last name can only contain letters, spaces, hyphens, and apostrophes.")
        return value

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError({"password": "Passwords must match"})
        try:
            validate_password(data['password'])
        except ValidationError as e:
            raise serializers.ValidationError({'password': list(e.messages)})
        return data

    def create(self, validated_data):
        validated_data.pop('password2', None)
        validated_data['email'] = validated_data['email'].lower().strip()
        validated_data['username'] = validated_data['username'].strip()
        
        # Clean name fields
        validated_data['first_name'] = validated_data.get('first_name', '').strip()
        validated_data['last_name'] = validated_data.get('last_name', '').strip()
        
        user = CustomUser.objects.create_user(**validated_data)
        return user

class ProfileSerializer(serializers.ModelSerializer):
    """Serializer for profile data"""
    profile_photo = serializers.SerializerMethodField()
    full_name = serializers.SerializerMethodField()
    age = serializers.SerializerMethodField()
    current_profile_photo = serializers.SerializerMethodField()

    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'profile_photo', 'bio', 'phone_number', 'date_of_birth', 
            'location', 'is_private', 'email_verified', 'phone_verified',
            'date_joined', 'updated_at', 'current_profile_photo', 'age'
        ]
        read_only_fields = ['id', 'username', 'email', 'date_joined', 'updated_at']

    def get_profile_photo(self, obj):
        """Return profile photo URL for upload field"""
        if obj.profile_photo:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_photo.url)
        return None

    def get_current_profile_photo(self, obj):
        """Return current profile photo URL for display"""
        if obj.profile_photo:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_photo.url)
        return None

    def get_full_name(self, obj):
        """Return full name"""
        full_name = f"{obj.first_name} {obj.last_name}".strip()
        return full_name if full_name else obj.username

    def get_age(self, obj):
        """Return calculated age"""
        if hasattr(obj, 'date_of_birth') and obj.date_of_birth:
            today = timezone.now().date()
            return today.year - obj.date_of_birth.year - (
                (today.month, today.day) < (obj.date_of_birth.month, obj.date_of_birth.day)
            )
        return None

    def validate_profile_photo(self, value):
        """Validate profile photo"""
        if value:
            # Validate file size (max 2MB)
            if value.size > 2 * 1024 * 1024:
                raise serializers.ValidationError("Profile photo size should not exceed 2MB.")
            # Validate file type
            if not value.name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                raise serializers.ValidationError("Profile photo must be PNG, JPEG, or GIF.")
        return value

    def validate_bio(self, value):
        """Validate bio length"""
        if value and len(value) > 500:
            raise serializers.ValidationError("Bio cannot exceed 500 characters.")
        return value

    def validate_first_name(self, value):
        """Validate first name format"""
        if value:
            value = value.strip()
            if len(value) > 30:
                raise serializers.ValidationError("First name cannot exceed 30 characters.")
            if not re.match(r'^[a-zA-Z\s\-\']+$', value):
                raise serializers.ValidationError("First name can only contain letters, spaces, hyphens, and apostrophes.")
        return value

    def validate_last_name(self, value):
        """Validate last name format"""
        if value:
            value = value.strip()
            if len(value) > 30:
                raise serializers.ValidationError("Last name cannot exceed 30 characters.")
            if not re.match(r'^[a-zA-Z\s\-\']+$', value):
                raise serializers.ValidationError("Last name can only contain letters, spaces, hyphens, and apostrophes.")
        return value

    def update(self, instance, validated_data):
        """Custom update logic for profile"""
        # Update basic fields
        instance.first_name = validated_data.get('first_name', instance.first_name).strip()
        instance.last_name = validated_data.get('last_name', instance.last_name).strip()
        instance.bio = validated_data.get('bio', instance.bio)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)
        instance.date_of_birth = validated_data.get('date_of_birth', instance.date_of_birth)
        instance.location = validated_data.get('location', instance.location)
        instance.is_private = validated_data.get('is_private', instance.is_private)
        
        # Update profile photo if provided
        if 'profile_photo' in validated_data:
            instance.profile_photo = validated_data['profile_photo']
        
        instance.save()
        return instance

class PasswordChangeSerializer(serializers.Serializer):
    """Serializer for changing user password"""
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=8)
    new_password2 = serializers.CharField(required=True, write_only=True)

    def validate_current_password(self, value):
        """Validate current password"""
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate_new_password(self, value):
        """Validate new password strength"""
        try:
            validate_password(value, self.context['request'].user)
        except ValidationError as e:
            raise serializers.ValidationError({'new_password': list(e.messages)})
        return value

    def validate(self, data):
        """Validate password confirmation"""
        if data['new_password'] != data['new_password2']:
            raise serializers.ValidationError({"new_password": "New passwords must match"})
        return data