import logging
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.utils import IntegrityError
from django.utils import timezone
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import Employee
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework.views import APIView
from .serializers import UserSerializer
from .throttles import LoginThrottle
import re
from .models import Notification  


logger = logging.getLogger(__name__)
User = get_user_model()

class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

class CookieTokenRefreshSerializer(TokenRefreshSerializer):
    refresh = None
    def validate(self, attrs):
        # Try cookie first, then request body for SPA compatibility
        request = self.context['request']
        refresh_token = request.COOKIES.get('refresh_token') or request.data.get('refresh')
        if refresh_token:
            attrs['refresh'] = refresh_token
            return super().validate(attrs)
        else:
            raise InvalidToken('No valid token found in cookie or body')

class CookieTokenRefreshView(TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        # Also set new refresh token in cookie if provided
        if 'refresh' in response.data:
            response.set_cookie(
                key='refresh_token',
                value=response.data['refresh'],
                httponly=True,
                secure=False,  # Set True in production
                path="/"
            )
        return response

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginThrottle])
def login_view(request):
    """Login endpoint - returns both tokens in body for SPA storage"""
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response(
            {'error': 'Username and password are required'},
            status=status.HTTP_400_BAD_REQUEST
        )
        
    user = authenticate(request, username=username, password=password)
    
    if not user:
        logger.warning(f"Failed login attempt for {username} from {request.META.get('REMOTE_ADDR')}")
        return Response(
            {'error': 'Invalid credentials'},
            status=status.HTTP_401_UNAUTHORIZED
        )
        
    logger.info(f"Successful login for {username} from {request.META.get('REMOTE_ADDR')}")
        
    refresh = RefreshToken.for_user(user)
        
    # Get employee_id if user has employee profile
    employee_id = None
    if hasattr(user, 'employee_profile'):
        employee_id = user.employee_profile.employee_id

    response = Response({
        'access': str(refresh.access_token),
        'refresh': str(refresh),  # ADDED: Return refresh in body for localStorage
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'employee_id': employee_id,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_superuser': user.is_superuser,
            'is_company_admin': getattr(user, 'is_company_admin', False),
            'is_payment_admin': getattr(user, 'is_payment_admin', False),
            'is_deduction_admin': getattr(user, 'is_deduction_admin', False),
            'is_employee_admin': getattr(user, 'is_employee_admin', False),
        }
    }, status=status.HTTP_200_OK)

    # Also set refresh token in HttpOnly cookie as backup
    response.set_cookie(
        key='refresh_token',
        value=str(refresh),
        httponly=True,
        secure=False,  # Set to True in production
        path="/"
    )

    return response


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register_view(request):
    data = request.data
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'staff')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    full_name = (data.get('full_name') or '').strip()
    current_user = request.user
    employee_id = data.get('employee_id')  # May be provided from frontend
        # Role validation
    if role not in ['admin', 'staff', 'guard']:
        return Response(
            {'error': 'Invalid role. Must be admin, staff, or guard'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if current_user.is_superuser:
        pass
    else:
        if current_user.role == 'admin' and role == 'admin':
            return Response(
                {'error': 'Admin users cannot create other admin users'},
                status=status.HTTP_403_FORBIDDEN
            )
        if current_user.role in ['staff', 'guard']:
            return Response(
                {'error': 'Only admin users can create new users'},
                status=status.HTTP_403_FORBIDDEN
            )
    
    if not username or not password:
        return Response(
            {'error': 'Username and password are required'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        validate_password(password)
    except ValidationError as e:
        return Response(
            {'error': e.messages},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # DUPLICATE DETECTION: Check username
    if User.objects.filter(username=username).exists():
        return Response(
            {'error': 'Username already exists', 'field': 'username'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # DUPLICATE DETECTION: Check email if provided
    email = data.get('email')
    if email and User.objects.filter(email__iexact=email).exists():
        return Response(
            {'error': 'Email already registered', 'field': 'email'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # DUPLICATE DETECTION: Check account number if provided
    account_number = data.get('account_number')
    bank_name = data.get('bank_name')
    if account_number and bank_name:
        if Employee.objects.filter(
            account_number=account_number,
            bank_name=bank_name,
            status__in=['active', 'terminated']  # Check active and terminated
        ).exists():
            return Response(
                {
                    'error': 'Bank account already registered to another employee',
                    'field': 'account_number',
                    'message': 'This account number is already in use'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
    
    # Employee validation fields
    if role in ['staff', 'guard']:
        required_fields = ['salary', 'location', 'bank_name', 'account_number', 'account_holder']
        missing = [f for f in required_fields if not data.get(f)]
        if missing:
            return Response(
                {'error': f'Missing required fields: {", ".join(missing)}'},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    try:
        with transaction.atomic():
            if full_name and not first_name and not last_name:
                name_parts = full_name.split(None, 1)
                first_name = name_parts[0]
                last_name = name_parts[1] if len(name_parts) > 1 else ''
            user = User.objects.create_user(
                username=username,
                password=password,
                email=email,
                role=role
            )
            user.first_name = first_name or ''
            user.last_name = last_name or ''
            user.save()
            employee = None
            if role in ['staff', 'guard']:
                employee_name = full_name or f"{first_name or ''} {last_name or ''}".strip() or username

                # Prepare employee data
                employee_data = {
                    'user': user,
                    'name': employee_name,
                    'type': role,
                    'location': data.get('location'),
                    'salary': data.get('salary'),
                    'phone': data.get('phone', ''),
                    'email': email,
                    'bank_name': data.get('bank_name'),
                    'bank_code': data.get('bank_code') or '',
                    'account_number': data.get('account_number'),
                    'account_holder': data.get('account_holder'),
                    'join_date': timezone.now().date()
                }
                
                # If employee_id provided (from preview), check it's still available
                if employee_id:
                    if Employee.objects.filter(employee_id=employee_id).exists():
                        # ID was taken, let model generate new one
                        employee_data.pop('employee_id', None)
                    else:
                        employee_data['employee_id'] = employee_id
                
                employee = Employee.objects.create(**employee_data)
                # Refresh to get the actual generated ID
                employee.refresh_from_db()
        return Response(
            {
                'message': 'User created successfully',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                },
                'employee': (
                    {
                        'id': str(employee.id),
                        'employee_id': employee.employee_id,
                        'name': employee.name,
                        'type': employee.type,
                        'sequence': employee.id_sequence,
                    } if employee else None
                )
            },
            status=status.HTTP_201_CREATED
        )
    
    except IntegrityError as e:
        logger.error(f"Integrity error during registration: {e}")
        return Response(
            {'error': 'Employee ID conflict detected. Please try again.'},
            status=status.HTTP_409_CONFLICT
        )
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return Response(
            {'error': 'Registration failed. Please try again.'},
            status=status.HTTP_400_BAD_REQUEST
        )
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    try:
        refresh_token = request.COOKIES.get('refresh_token') or request.data.get('refresh')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()

        response = Response({"detail": "Successfully logged out."}, status=status.HTTP_200_OK)
        response.delete_cookie('refresh_token')
        return response
    except Exception as e:
        logger.error(f"Logout error: {e}")
        response = Response({"detail": "Logout failed, but cookie cleared."}, status=status.HTTP_400_BAD_REQUEST)
        response.delete_cookie('refresh_token')
        return response

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_password(request):
    """Confirm current password matches input. Used by frontend exports."""
    pwd = request.data.get('password')
    if not pwd:
        return Response({'error': 'Password is required'}, status=status.HTTP_400_BAD_REQUEST)
    if request.user.check_password(pwd):
        return Response({'valid': True}, status=status.HTTP_200_OK)
    return Response({'valid': False}, status=status.HTTP_401_UNAUTHORIZED)


    # NEW: Endpoint to get next employee ID for preview
@api_view(['GET'])
@permission_classes([AllowAny])
def get_next_employee_id(request):
    """Get next auto-generated employee ID for preview (does NOT reserve it)"""
    employee_type = request.query_params.get('type', 'staff')
    
    # Get the last sequence used globally
    last_employee = Employee.objects.order_by('-id_sequence').first()
    next_sequence = (last_employee.id_sequence + 1) if last_employee and last_employee.id_sequence else 1
    
    # Format preview ID
    if employee_type == 'staff':
        suffix = 'STAFF'
    elif employee_type == 'guard':
        suffix = 'GRD'
    else:
        suffix = 'EMP'
    
    next_id = f"FSS-{str(next_sequence).zfill(3)}-{suffix}"
    
    return Response({
        'next_id': next_id,
        'type': employee_type,
        'sequence': next_sequence,
        'note': 'This is a preview. Actual ID assigned on creation.'
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    """Change user password with confirmation and superuser notification"""
    user = request.user
    old_password = request.data.get('old_password')
    new_password = request.data.get('new_password')
    confirm_password = request.data.get('confirm_password')
    
    if not old_password or not new_password or not confirm_password:
        return Response({'error': 'All password fields are required'}, status=status.HTTP_400_BAD_REQUEST)
    
    if new_password != confirm_password:
        return Response({'error': 'New passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
    
    if not user.check_password(old_password):
        return Response({'error': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Validate new password strength
    from django.contrib.auth.password_validation import validate_password
    try:
        validate_password(new_password, user)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    # Change password
    user.set_password(new_password)
    user.save()
    
    # Notify superuser
    superusers = User.objects.filter(is_superuser=True)
    for superuser in superusers:
        Notification.objects.create(
            user=superuser,
            title='Password Changed',
            message=f'User {user.username} ({user.get_full_name() or user.email}) changed their password.',
            notification_type='security'
        )
    
    # Log the change
    logger.info(f"Password changed for user {user.username} by {request.user.username}")
    
    return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
