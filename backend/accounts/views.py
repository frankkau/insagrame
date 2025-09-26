# accounts/views.py
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import authenticate
from django.utils import timezone
from .serializers import (
    LoginSerializer, 
    RegisterSerializer, 
    ProfileSerializer
)
from .models import CustomUser
import logging

logger = logging.getLogger(__name__)

class LoginView(APIView):
    """Custom login view"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        logger.info(f"Login attempt for email: {request.data.get('email')}")
        
        serializer = LoginSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            data = serializer.validated_data
            
            logger.info(f"Login successful for user: {data['user']['email']}")
            
            return Response({
                'access': data['access'],
                'refresh': data['refresh'],
                'user': data['user']
            }, status=status.HTTP_200_OK)
        
        logger.error(f"Login failed: {serializer.errors}")
        return Response({
            'error': 'Login failed',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class RegisterView(APIView):
    """User registration view"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        logger.info(f"Registration attempt for: {request.data.get('email')}")
        
        # Validate required fields
        required_fields = ['username', 'email', 'password']
        missing_fields = [field for field in required_fields if not request.data.get(field)]
        if missing_fields:
            return Response({
                'error': f'Missing required fields: {", ".join(missing_fields)}'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            
            # Serialize user data
            user_serializer = ProfileSerializer(user, context={'request': request})
            
            logger.info(f"User registered successfully: {user.email}")
            return Response({
                'message': 'User registered successfully',
                'user': user_serializer.data,
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
            }, status=status.HTTP_201_CREATED)
        
        logger.error(f"Registration failed: {serializer.errors}")
        return Response({
            'error': 'Registration failed',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(APIView):
    """Profile management view"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get user profile"""
        serializer = ProfileSerializer(request.user, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        """Update user profile"""
        logger.info(f"Profile update attempt by user: {request.user.email}")
        
        # FIXED: Correct way to handle file uploads with ModelSerializer
        # Create a combined data dict for the serializer
        data_dict = {}
        
        # Handle form data (multipart/form-data)
        if request.content_type and 'multipart/form-data' in request.content_type:
            # File upload - use request.FILES
            data_dict = {
                **request.data.dict(),  # Form fields
                **{k: v for k, v in request.FILES.items()}  # File fields
            }
        else:
            # JSON data
            data_dict = request.data
        
        serializer = ProfileSerializer(
            request.user, 
            data=data_dict,  # FIXED: Only pass data, not files parameter
            partial=True, 
            context={'request': request}
        )
        
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'message': 'Profile updated successfully',
                'user': ProfileSerializer(user, context={'request': request}).data
            }, status=status.HTTP_200_OK)
        
        logger.error(f"Profile update failed: {serializer.errors}")
        return Response({
            'error': 'Failed to update profile',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    """Logout view"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """Logout user by blacklisting refresh token"""
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()
            
            return Response({
                'message': 'Successfully logged out'
            }, status=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            return Response({
                'error': 'Invalid refresh token'
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response({
                'error': 'Failed to logout'
            }, status=status.HTTP_400_BAD_REQUEST)

class TokenRefreshView(APIView):
    """Token refresh view"""
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get('refresh')
        
        if not refresh_token:
            return Response({
                'error': 'Refresh token is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            token = RefreshToken(refresh_token)
            new_access = str(token.access_token)
            
            return Response({
                'access': new_access
            }, status=status.HTTP_200_OK)
        except TokenError:
            return Response({
                'error': 'Invalid or expired refresh token'
            }, status=status.HTTP_401_UNAUTHORIZED)