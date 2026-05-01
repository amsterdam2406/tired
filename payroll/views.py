import hmac
import hashlib
import requests
import logging
from django.contrib.auth import get_user_model
from django.shortcuts import render
from django.conf import settings
from django.db.models import Sum
from django.db import transaction
from django.utils import timezone
from datetime import datetime, timedelta
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework import viewsets, status, serializers
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from decimal import Decimal
import csv
import uuid
import base64
import secrets
import random
import string
from django.http import HttpResponse, JsonResponse
from django.core.files.base import ContentFile
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from .models import (
    Employee, Attendance, Deduction, Payment,
    Company, SackedEmployee, Notification, OTP, ExportToken
)
from .serializers import (
    UserSerializer, EmployeeSerializer, AttendanceSerializer,
    DeductionSerializer, PaymentSerializer, CompanySerializer,
    SackedEmployeeSerializer, NotificationSerializer
)
from .paystack import PaystackAPI, NIGERIAN_BANKS
from .permissions import (
    IsAdmin, CanCreateEmployee, IsSackAdmin, IsPayrollAdmin,
    IsDeductionAdmin, CanEditNotification, CanViewAndEditCompany
)
from payroll.throttles import AttendanceThrottle, PaymentThrottle, BulkPaymentThrottle, ExportThrottle
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.throttling import ScopedRateThrottle

User = get_user_model()
logger = logging.getLogger(__name__)


def get_employee_bank_code(employee):
    bank_code = getattr(employee, 'bank_code', None)
    if bank_code:
        return bank_code

    normalized_name = (employee.bank_name or '').strip().lower()
    for code, name in NIGERIAN_BANKS.items():
        if normalized_name == (name or '').strip().lower():
            if hasattr(employee, 'bank_code'):
                employee.bank_code = code
                employee.save(update_fields=['bank_code'])
            return code
    return None


# ─────────────────────────────────────────
# PAYSTACK BANK UTILITIES
# ─────────────────────────────────────────

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def paystack_banks(request):
    """Get list of Nigerian banks from Paystack"""
    paystack = PaystackAPI()
    result = paystack.get_banks()
    return Response(result)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def paystack_verify_account(request):
    """Verify bank account number"""
    account_number = request.data.get('account_number')
    bank_code = request.data.get('bank_code')

    if not account_number or not bank_code:
        return Response(
            {'error': 'account_number and bank_code required'},
            status=status.HTTP_400_BAD_REQUEST
        )

    paystack = PaystackAPI()
    result = paystack.verify_account(account_number, bank_code)

    if result.get('error_code') == 'rate_limited':
        retry_after = result.get('retry_after')
        message = result.get('message', 'Account verification temporarily rate limited.')
        if retry_after:
            message = f"{message} Retry after {retry_after} seconds."
        return Response({'detail': message}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    return Response(result)


# ─────────────────────────────────────────
# PAYSTACK WEBHOOK HANDLER
# ─────────────────────────────────────────

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def paystack_webhook(request):
    """
    Handle Paystack webhook events.
    Must be registered in Paystack dashboard settings.
    Paystack sends POST requests here for transfer.success,
    transfer.failed, transfer.reversed events.
    """
    paystack_secret = getattr(settings, 'PAYSTACK_SECRET_KEY', '')
    signature = request.headers.get('x-paystack-signature', '')

    # Verify webhook signature to confirm it's from Paystack
    computed = hmac.new(
        paystack_secret.encode('utf-8'),
        request.body,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(computed, signature):
        logger.warning("Invalid Paystack webhook signature received")
        return HttpResponse(status=400)

    try:
        payload = request.data
        event = payload.get('event')
        data = payload.get('data', {})
        reference = data.get('reference')

        logger.info(f"Paystack webhook received: {event} for reference={reference}")

        if event == 'transfer.success':
            _handle_transfer_success(data)

        elif event == 'transfer.failed':
            _handle_transfer_failed(data)

        elif event == 'transfer.reversed':
            _handle_transfer_reversed(data)

        elif event == 'charge.success':
            # Handles collection payments if you use initialize_transaction
            _handle_charge_success(data)

        else:
            logger.info(f"Unhandled Paystack webhook event: {event}")

        # Always return 200 to Paystack so it doesn't retry
        return HttpResponse(status=200)

    except Exception as e:
        logger.error(f"Webhook processing error: {e}")
        # Still return 200 so Paystack doesn't keep retrying
        return HttpResponse(status=200)


def _handle_transfer_success(data):
    """Mark payment as completed when transfer succeeds"""
    reference = data.get('reference')
    try:
        payment = Payment.objects.get(transaction_reference=reference)

        if payment.status == 'completed':
            logger.info(f"Webhook: Payment {reference} already completed, skipping")
            return

        with transaction.atomic():
            payment.status = 'completed'
            payment.paystack_reference = str(data.get('id', ''))
            payment.save()

            # Mark all pending deductions as applied
            Deduction.objects.filter(
                employee=payment.employee,
                status='pending'
            ).update(status='applied')

            # Notify employee
            Notification.objects.create(
                user=payment.employee.user,
                message=(
                    f"Salary payment of ₦{payment.net_amount:,.2f} has been "
                    f"sent to your {payment.employee.bank_name} account."
                ),
                type='success'
            )

        logger.info(
            f"Transfer successful for {payment.employee.name}: "
            f"₦{payment.net_amount}"
        )

    except Payment.DoesNotExist:
        logger.error(f"Webhook transfer.success: Payment not found for reference={reference}")
    except Exception as e:
        logger.error(f"Webhook _handle_transfer_success error: {e}")


def _handle_transfer_failed(data):
    """Mark payment as failed when transfer fails"""
    reference = data.get('reference')
    try:
        payment = Payment.objects.get(transaction_reference=reference)

        if payment.status in ['completed', 'failed']:
            return

        payment.status = 'failed'
        payment.save()

        Notification.objects.create(
            user=payment.employee.user,
            message=(
                f"Salary payment of ₦{payment.net_amount:,.2f} failed. "
                f"Please contact HR for assistance."
            ),
            type='warning'
        )

        logger.error(
            f"Transfer failed for {payment.employee.name}: "
            f"reference={reference}"
        )

    except Payment.DoesNotExist:
        logger.error(f"Webhook transfer.failed: Payment not found for reference={reference}")
    except Exception as e:
        logger.error(f"Webhook _handle_transfer_failed error: {e}")


def _handle_transfer_reversed(data):
    """Mark payment as failed when transfer is reversed"""
    reference = data.get('reference')
    try:
        payment = Payment.objects.get(transaction_reference=reference)
        payment.status = 'failed'
        payment.save()

        Notification.objects.create(
            user=payment.employee.user,
            message=(
                f"Salary payment of ₦{payment.net_amount:,.2f} was reversed. "
                f"Please contact HR."
            ),
            type='warning'
        )

        logger.error(f"Transfer reversed for reference={reference}")

    except Payment.DoesNotExist:
        logger.error(f"Webhook transfer.reversed: Payment not found for reference={reference}")
    except Exception as e:
        logger.error(f"Webhook _handle_transfer_reversed error: {e}")


def _handle_charge_success(data):
    """
    Handle successful charge (used with initialize_transaction).
    Kept for future use if you collect payments.
    """
    reference = data.get('reference')
    try:
        payment = Payment.objects.get(transaction_reference=reference)

        if payment.status == 'completed':
            return

        with transaction.atomic():
            payment.status = 'completed'
            payment.paystack_reference = data.get('reference', '')
            payment.save()

            Deduction.objects.filter(
                employee=payment.employee,
                status='pending'
            ).update(status='applied')

            Notification.objects.create(
                user=payment.employee.user,
                message=f"Payment of ₦{payment.net_amount:,.2f} confirmed.",
                type='success'
            )

        logger.info(f"Charge successful for reference={reference}")

    except Payment.DoesNotExist:
        logger.error(f"Webhook charge.success: Payment not found for reference={reference}")
    except Exception as e:
        logger.error(f"Webhook _handle_charge_success error: {e}")


# ─────────────────────────────────────────
# USER VIEWSET
# ─────────────────────────────────────────

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('id')
    serializer_class = UserSerializer

    def get_permissions(self):
        if self.action == "export_csv":
            return [AllowAny()]
        if self.action == "create":
            return [IsAdmin()]
        if self.request.user.is_authenticated:
            if self.request.user.role in ['staff', 'guard']:
                if self.action in ['list', 'retrieve']:
                    return [IsAuthenticated()]
                return [IsAdmin()]
        return [IsAuthenticated()]

    def destroy(self, request, *args, **kwargs):
        if not (request.user.is_superuser or getattr(request.user, "is_employee_admin", False)):
            return Response(
                {"error": "Only admins can delete users"},
                status=status.HTTP_403_FORBIDDEN
            )
        return super().destroy(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return User.objects.all().order_by('id')
        if user.role == 'admin':
            return User.objects.filter(role__in=['staff', 'guard']).order_by('id')
        return User.objects.filter(id=user.id).order_by('id')

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def me(self, request):
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)


# ─────────────────────────────────────────
# EMPLOYEE VIEWSET
# ─────────────────────────────────────────

class EmployeeViewSet(viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication, SessionAuthentication, BasicAuthentication]
    queryset = Employee.objects.all().order_by('-created_at')
    serializer_class = EmployeeSerializer
    filterset_fields = ['type', 'status', 'location']
    search_fields = ['name', 'employee_id', 'email']

    def get_permissions(self):
        user = self.request.user
        if self.action == 'create':
            return [IsAuthenticated(), CanCreateEmployee()]
        if user.is_authenticated and user.role in ['staff', 'guard']:
            if self.action in ['list', 'retrieve']:
                return [IsAuthenticated()]
            return [IsAdmin()]
        return [IsAuthenticated()]

    def destroy(self, request, *args, **kwargs):
        employee = self.get_object()
        with transaction.atomic():
            employee.status = 'terminated'
            employee.save()
            SackedEmployee.objects.create(
                employee=employee,
                date_sacked=timezone.now().date(),
                offense='Deleted by admin',
                terminated_by=request.user
            )
            Notification.objects.create(
                user=employee.user,
                message=f"Employee {employee.employee_id} - {employee.name} has been terminated (deleted by admin).",
                type='warning'
            )
        return Response(
            {'message': 'Employee has been terminated and moved to sacked list'},
            status=status.HTTP_200_OK
        )

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == 'admin':
            return Employee.objects.filter(status='active').order_by('-created_at')
        return Employee.objects.filter(user=user, status='active').order_by('-created_at')

    def create(self, request, *args, **kwargs):
        print("Employee create payload:", request.data)
        return super().create(request, *args, **kwargs)

    def get_throttles(self):
        if self.action in ['request_export', 'export_csv']:
            return [ExportThrottle()]
        return []

    @action(detail=True, methods=['post'],
            permission_classes=[IsAuthenticated, IsSackAdmin])
    def terminate(self, request, pk=None):
        employee = self.get_object()
        offense = request.data.get('offense')

        if not offense:
            return Response({'error': 'Offense reason required'}, status=400)

        with transaction.atomic():
            SackedEmployee.objects.create(
                employee=employee,
                date_sacked=timezone.now().date(),
                offense=offense,
                terminated_by=request.user
            )
            employee.status = 'terminated'
            employee.save()

            Notification.objects.create(
                user=employee.user,
                message=f"Employee {employee.employee_id} - {employee.name} has been terminated. Reason: {offense}",
                type='warning'
            )

        logger.info(f"{request.user.username} terminated {employee.name}. Offense: {offense}")
        return Response({'message': 'Employee terminated successfully'})

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def dashboard_stats(self, request):
        """Get dashboard statistics"""
        active_employees = Employee.objects.filter(status='active')

        total_staff = active_employees.filter(type='staff').count()
        total_guards = active_employees.filter(type='guard').count()

        total_deductions = Deduction.objects.filter(
            status='pending'
        ).aggregate(Sum('amount'))['amount__sum'] or 0

        total_payments = 0
        for emp in active_employees:
            emp_deductions = Deduction.objects.filter(
                employee=emp, status='pending'
            ).aggregate(Sum('amount'))['amount__sum'] or 0
            total_payments += float(emp.salary - emp_deductions)

        recent_employees = Employee.objects.order_by('-created_at')[:5]
        recent_payments = Payment.objects.order_by('-created_at')[:5]

        return Response({
            'total_staff': total_staff,
            'total_guards': total_guards,
            'total_deductions': total_deductions,
            'total_payments': total_payments,
            'recent_employees': EmployeeSerializer(recent_employees, many=True).data,
            'recent_payments': PaymentSerializer(recent_payments, many=True).data
        })

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def request_export(self, request):
        """Request export token for employee data"""
        password = request.data.get('password')
        filters = request.data.get('filters', {})

        if not password or not request.user.check_password(password):
            return Response({'error': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)

        user = request.user
        if not (user.is_superuser or user.role == 'admin'):
            return Response({'error': 'Insufficient permissions'}, status=status.HTTP_403_FORBIDDEN)

        token = secrets.token_urlsafe(32)
        export_token = ExportToken.objects.create(
            user=user,
            token=token,
            data_type='employees',
            filters=filters,
            expires_at=timezone.now() + timezone.timedelta(minutes=10)
        )

        logger.info(f"Export token created for {user.username}")
        return Response({'token': token, 'expires_at': export_token.expires_at})

    @action(detail=False, methods=['get'], permission_classes=[AllowAny],
            authentication_classes=[SessionAuthentication, BasicAuthentication])
    def export_csv(self, request):
        """Export employee data as CSV using token"""
        token = request.query_params.get('token')
        if not token:
            return Response({'error': 'Token required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            export_token = ExportToken.objects.get(token=token, is_used=False)
            if export_token.is_expired():
                return Response({'error': 'Token expired'}, status=status.HTTP_400_BAD_REQUEST)

            export_token.is_used = True
            export_token.save()

            queryset = Employee.objects.all()
            filters = export_token.filters

            if filters.get('type'):
                queryset = queryset.filter(type=filters['type'])
            if filters.get('status'):
                queryset = queryset.filter(status=filters['status'])
            if filters.get('location'):
                queryset = queryset.filter(location=filters['location'])

            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="employees.csv"'

            writer = csv.writer(response)
            writer.writerow([
                'Employee ID', 'Name', 'Type', 'Location', 'Salary',
                'Email', 'Phone', 'Bank Name', 'Account Number',
                'Bank Code', 'Status', 'Join Date'
            ])

            for employee in queryset:
                writer.writerow([
                    employee.employee_id,
                    employee.name,
                    employee.type,
                    employee.location,
                    employee.salary,
                    employee.email or '',
                    employee.phone or '',
                    employee.bank_name,
                    employee.account_number,
                    getattr(employee, 'bank_code', ''),
                    employee.status,
                    employee.join_date
                ])

            logger.info(f"Employee export completed for {export_token.user.username}")
            return response

        except ExportToken.DoesNotExist:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


# ─────────────────────────────────────────
# ATTENDANCE VIEWSET
# ─────────────────────────────────────────

class AttendanceViewSet(viewsets.ModelViewSet):
    queryset = Attendance.objects.all().order_by('id')
    serializer_class = AttendanceSerializer
    filterset_fields = ['employee', 'date', 'status']
    throttle_classes = [AttendanceThrottle]

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return Attendance.objects.none()
        if user.is_superuser or user.role == 'admin':
            return Attendance.objects.all().order_by('id')
        try:
            employee = Employee.objects.get(user=user)
            return Attendance.objects.filter(employee=employee).order_by('id')
        except Employee.DoesNotExist:
            return Attendance.objects.none()

    def get_permissions(self):
        if self.action == 'process_absence_deductions':
            return [IsAdmin()]
        return [IsAuthenticated()]

    def get_throttles(self):
        if self.action in ['clock_in_with_photo', 'clock_out_with_photo',
                           'clock_in', 'clock_out', 'create', 'update', 'partial_update']:
            return [AttendanceThrottle()]
        return []

    def perform_create(self, serializer):
        serializer.save()

    def _get_employee(self, request):
        employee_id = request.data.get('employee_id') or request.data.get('employee')
        can_select_employee = (
            request.user.is_superuser
            or request.user.role == 'admin'
            or getattr(request.user, 'is_employee_admin', False)
            or getattr(request.user, 'is_staff', False)
        )
        if can_select_employee:
            if employee_id:
                return Employee.objects.get(
                    Q(id=employee_id) | Q(employee_id=employee_id),
                    status='active'
                )
        return Employee.objects.get(user=request.user)

    @staticmethod
    def _decode_photo(photo_data):
        if not photo_data:
            raise ValueError("No photo provided")
        if ';base64,' in photo_data:
            header, imgstr = photo_data.split(';base64,', 1)
            ext = header.split('/')[-1] if '/' in header else 'jpg'
            ext = ext.replace('jpeg', 'jpg')
        elif 'base64' in photo_data:
            parts = photo_data.split('base64', 1)
            if len(parts) == 2:
                imgstr = parts[1].lstrip(',;:')
                ext = 'jpg'
            else:
                raise ValueError("Invalid photo format")
        else:
            imgstr = photo_data
            ext = 'jpg'
        try:
            return ext, base64.b64decode(imgstr)
        except Exception:
            raise ValueError("Invalid base64 data")

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def clock_in(self, request):
        try:
            employee = self._get_employee(request)
        except Employee.DoesNotExist:
            return Response({'error': 'Employee profile not found'}, status=status.HTTP_404_NOT_FOUND)

        attendance, created = Attendance.objects.get_or_create(
            employee=employee, date=timezone.now().date()
        )
        if attendance.clock_in_timestamp:
            return Response({'error': 'Already clocked in today'}, status=status.HTTP_400_BAD_REQUEST)

        attendance.clock_in_timestamp = timezone.now()
        attendance.clock_in = timezone.now().time()
        attendance.status = 'present'
        attendance.save()
        logger.info(f"{request.user.username} clocked in without photo")
        return Response({'message': 'Clocked in successfully', 'status': 'present'})

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def clock_in_with_photo(self, request):
        try:
            employee = self._get_employee(request)
        except Employee.DoesNotExist:
            return Response({'error': 'Employee profile not found'}, status=status.HTTP_404_NOT_FOUND)

        photo_data = request.data.get('photo')
        if not photo_data:
            return Response({'error': 'Photo is required for attendance'}, status=status.HTTP_400_BAD_REQUEST)

        attendance, created = Attendance.objects.get_or_create(
            employee=employee, date=timezone.now().date()
        )
        if attendance.clock_in_timestamp:
            return Response({'error': 'Already clocked in today'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            ext, image_data = self._decode_photo(photo_data)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        attendance.clock_in_photo.save(
            f'clockin_{employee.id}_{timezone.now().timestamp()}.{ext}',
            ContentFile(image_data), save=False
        )
        attendance.clock_in_timestamp = timezone.now()
        attendance.clock_in = timezone.now().time()
        attendance.status = 'present'
        attendance.save()
        logger.info(f"{request.user.username} clocked in with photo")
        return Response({'message': 'Clocked in successfully', 'status': 'present'})

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def clock_out(self, request):
        try:
            employee = self._get_employee(request)
        except Employee.DoesNotExist:
            return Response({'error': 'Employee profile not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            attendance = Attendance.objects.get(employee=employee, date=timezone.now().date())
        except Attendance.DoesNotExist:
            return Response({'error': 'No clock-in record found for today'}, status=status.HTTP_404_NOT_FOUND)

        if attendance.clock_out_timestamp:
            return Response({'error': 'Already clocked out today'}, status=status.HTTP_400_BAD_REQUEST)

        attendance.clock_out_timestamp = timezone.now()
        attendance.clock_out = timezone.now().time()
        attendance.save()
        logger.info(f"{request.user.username} clocked out without photo")
        return Response({'message': 'Clocked out successfully'})

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def clock_out_with_photo(self, request):
        try:
            employee = self._get_employee(request)
        except Employee.DoesNotExist:
            return Response({'error': 'Employee profile not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            attendance = Attendance.objects.get(employee=employee, date=timezone.now().date())
        except Attendance.DoesNotExist:
            return Response({'error': 'No clock-in record found for today'}, status=status.HTTP_404_NOT_FOUND)

        if attendance.clock_out_timestamp:
            return Response({'error': 'Already clocked out today'}, status=status.HTTP_400_BAD_REQUEST)

        photo_data = request.data.get('photo')
        if not photo_data:
            return Response({'error': 'Photo is required for clock out'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            ext, image_data = self._decode_photo(photo_data)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        attendance.clock_out_photo.save(
            f'clockout_{employee.id}_{timezone.now().timestamp()}.{ext}',
            ContentFile(image_data), save=False
        )
        attendance.clock_out_timestamp = timezone.now()
        attendance.clock_out = timezone.now().time()
        attendance.status = 'present'
        attendance.save()
        logger.info(f"{request.user.username} clocked out with photo")
        return Response({'message': 'Clocked out successfully'})

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def mark_leave(self, request):
        employee_id = request.data.get('employee_id')
        start_date = request.data.get('start_date')
        end_date = request.data.get('end_date')
        reason = request.data.get('reason', '')

        if not all([employee_id, start_date, end_date]):
            return Response(
                {'error': 'employee_id, start_date, and end_date are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            employee = Employee.objects.get(id=employee_id)
        except Employee.DoesNotExist:
            return Response({'error': 'Employee not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            start = datetime.strptime(start_date, '%Y-%m-%d').date()
            end = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            return Response({'error': 'Invalid date format. Use YYYY-MM-DD'}, status=status.HTTP_400_BAD_REQUEST)

        if start > end:
            return Response({'error': 'Start date cannot be after end date'}, status=status.HTTP_400_BAD_REQUEST)

        leave_records = []
        current = start
        while current <= end:
            attendance, created = Attendance.objects.get_or_create(
                employee=employee,
                date=current,
                defaults={'status': 'leave', 'clock_in': None, 'clock_out': None}
            )
            if not created and not attendance.clock_in_timestamp:
                attendance.status = 'leave'
                attendance.save()

            leave_records.append({'date': current.isoformat(), 'status': attendance.status})
            current += timedelta(days=1)

        Notification.objects.create(
            user=employee.user,
            message=f"Leave marked from {start_date} to {end_date}. Reason: {reason}",
            type='info'
        )

        return Response({'message': f'Leave marked for {len(leave_records)} days', 'records': leave_records})

    @action(detail=False, methods=['post'], permission_classes=[IsAdmin])
    def process_absence_deductions(self, request):
        end_date = timezone.now().date()
        start_date = end_date - timezone.timedelta(days=10)

        employees = Employee.objects.filter(status='active')
        processed_deductions = []
        errors = []

        for employee in employees:
            try:
                attendance_dates = set(
                    Attendance.objects.filter(
                        employee=employee,
                        date__range=[start_date, end_date]
                    ).values_list('date', flat=True)
                )

                all_dates = set()
                current_date = start_date
                while current_date <= end_date:
                    if current_date.weekday() < 5:
                        all_dates.add(current_date)
                    current_date += timezone.timedelta(days=1)

                absences = sorted(all_dates - attendance_dates)

                max_consecutive = 0
                consecutive = 0
                prev_date = None

                for absence_date in absences:
                    if prev_date is None or (absence_date - prev_date).days == 1:
                        consecutive += 1
                        max_consecutive = max(max_consecutive, consecutive)
                    else:
                        consecutive = 1
                    prev_date = absence_date

                if max_consecutive >= 3:
                    deduction_amount = (employee.salary / 30) * max_consecutive
                    deduction_data = {
                        'employee': employee,
                        'amount': deduction_amount,
                        'reason': f'Absence deduction: {max_consecutive} consecutive days absent',
                        'status': 'pending',
                        'date': timezone.now().date(),
                    }
                    try:
                        Deduction.objects.create(**deduction_data, created_by=request.user)
                    except TypeError:
                        Deduction.objects.create(**deduction_data)

                    processed_deductions.append({
                        'employee': employee.name,
                        'consecutive_absences': max_consecutive,
                        'deduction_amount': deduction_amount
                    })
                    logger.info(f"Created absence deduction for {employee.name}: {deduction_amount}")

            except Exception as e:
                errors.append(f"Error processing {employee.name}: {str(e)}")
                logger.error(f"Error processing absence deductions for {employee.name}: {e}")

        return Response({
            'message': f'Processed deductions for {len(processed_deductions)} employees',
            'deductions': processed_deductions,
            'errors': errors
        })


# ─────────────────────────────────────────
# PAYMENT VIEWSET
# ─────────────────────────────────────────

class PaymentViewSet(viewsets.ModelViewSet):
    queryset = Payment.objects.all().order_by('id')
    serializer_class = PaymentSerializer
    filterset_fields = ['employee', 'status', 'payment_date']
    throttle_classes = [PaymentThrottle]

    def get_permissions(self):
        if self.action in ["initiate_payment", "create", "update", "partial_update", "destroy"]:
            return [IsAuthenticated(), IsPayrollAdmin()]
        return [IsAuthenticated()]

    def get_throttles(self):
        if self.action == 'bulk_payment':
            return [BulkPaymentThrottle()]
        elif self.action in ['initiate_payment', 'create']:
            return [PaymentThrottle()]
        return []

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == 'admin' or getattr(user, 'is_payment_admin', False):
            return Payment.objects.all().order_by('id')
        return Payment.objects.filter(employee__user=user).order_by('id')

    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated, IsPayrollAdmin])
    def paystack_balance(self, request):
        """
        NEW: Check Paystack wallet balance before running payroll.
        Warn admin if balance is insufficient.
        """
        paystack = PaystackAPI()
        result = paystack.get_transfer_balance()

        if result.get('status'):
            balances = result.get('data', [])
            ngn_balance = next(
                (b for b in balances if b.get('currency') == 'NGN'), None
            )
            if ngn_balance:
                balance_kobo = ngn_balance.get('balance', 0)
                balance_naira = balance_kobo / 100
                return Response({
                    'balance': balance_naira,
                    'balance_formatted': f"₦{balance_naira:,.2f}",
                    'currency': 'NGN'
                })

        return Response(
            {'error': 'Could not fetch balance', 'detail': result.get('message')},
            status=status.HTTP_400_BAD_REQUEST
        )

    @action(detail=False, methods=['post'],
            permission_classes=[IsAuthenticated, IsPayrollAdmin, IsAdmin])
    def initiate_payment(self, request):
        """
        UPDATED: Now uses Paystack Transfers (salary payout)
        instead of initialize_transaction (card collection).
        Flow: create/reuse recipient → initiate transfer →
        webhook confirms success.
        """
        employee_id = request.data.get('employee_id')
        if not employee_id:
            return Response({'error': 'Employee ID required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            employee = Employee.objects.get(id=employee_id, status='active')
        except Employee.DoesNotExist:
            return Response({'error': 'Employee not found or not active'}, status=status.HTTP_404_NOT_FOUND)

        # Validate bank details
        if not employee.account_number or not employee.bank_name:
            return Response(
                {'error': 'Employee has no bank account details'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # bank_code is required for Paystack transfers
        bank_code = get_employee_bank_code(employee)
        if not bank_code:
            return Response(
                {'error': 'Employee bank_code is missing. Update employee record first.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        with transaction.atomic():
            pending_deductions = Deduction.objects.filter(
                employee=employee, status='pending'
            ).aggregate(Sum('amount'))['amount__sum'] or 0

            net_salary = employee.salary - pending_deductions

            if net_salary <= 0:
                return Response(
                    {'error': 'Net salary is zero or negative after deductions'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            payment = Payment.objects.create(
                employee=employee,
                base_salary=employee.salary,
                total_deductions=pending_deductions,
                net_amount=net_salary,
                transaction_reference=str(uuid.uuid4()),
                payment_date=timezone.now().date(),
                processed_by=request.user,
                status='processing',
                payment_method='bank_transfer'
            )

            paystack = PaystackAPI()

            # Step 1: Get or create recipient
            # Reuse stored recipient_code if available to avoid duplicates
            recipient_code = getattr(employee, 'paystack_recipient_code', None)

            if not recipient_code:
                recipient_result = paystack.create_recipient(
                    name=employee.name,
                    account_number=employee.account_number,
                    bank_code=bank_code
                )

                if not recipient_result.get('status'):
                    payment.status = 'failed'
                    payment.save()
                    return Response(
                        {'error': f"Failed to create recipient: {recipient_result.get('message')}"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                recipient_code = recipient_result['recipient_code']

                # Save recipient_code to employee if field exists
                if hasattr(employee, 'paystack_recipient_code'):
                    employee.paystack_recipient_code = recipient_code
                    employee.save(update_fields=['paystack_recipient_code'])

            # Step 2: Initiate transfer
            transfer_result = paystack.initiate_transfer(
                amount=int(net_salary * 100),
                recipient_code=recipient_code,
                reference=payment.transaction_reference,
                reason=f"Salary - {employee.name} ({employee.employee_id})"
            )

            if transfer_result.get('status'):
                transfer_status = transfer_result.get('data', {}).get('status', 'pending')
                logger.info(
                    f"{request.user.username} initiated salary transfer for "
                    f"{employee.name}: ₦{net_salary} (status={transfer_status})"
                )
                return Response({
                    'message': 'Salary transfer initiated successfully',
                    'reference': payment.transaction_reference,
                    'transfer_status': transfer_status,
                    'amount': float(net_salary),
                    'employee': employee.name,
                    'bank': employee.bank_name,
                    'account': employee.account_number,
                    # transfer.success webhook will mark it completed
                    'note': 'Payment will be confirmed automatically via webhook'
                })
            else:
                payment.status = 'failed'
                payment.save()
                return Response(
                    {'error': f"Transfer failed: {transfer_result.get('message')}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated, IsPayrollAdmin])
    def bulk_payment(self, request):
        """
        UPDATED: Uses bulk_transfer for efficiency instead of
        looping individual transfers.
        """
        employee_ids = request.data.get('employee_ids', [])
        if not employee_ids:
            return Response({'error': 'No employees selected'}, status=status.HTTP_400_BAD_REQUEST)

        paystack = PaystackAPI()
        payments_created = []
        transfers_payload = []
        errors = []
        total_amount = 0

        for emp_id in employee_ids:
            try:
                employee = Employee.objects.get(id=emp_id, status='active')

                bank_code = get_employee_bank_code(employee)
                if not bank_code:
                    errors.append(f"{employee.name}: missing bank_code")
                    continue

                pending_deductions = Deduction.objects.filter(
                    employee=employee, status='pending'
                ).aggregate(Sum('amount'))['amount__sum'] or 0

                net_amount = employee.salary - pending_deductions
                total_amount += float(net_amount)

                payment = Payment.objects.create(
                    employee=employee,
                    base_salary=employee.salary,
                    total_deductions=pending_deductions,
                    net_amount=net_amount,
                    transaction_reference=str(uuid.uuid4()),
                    payment_date=timezone.now().date(),
                    processed_by=request.user,
                    status='processing',
                    payment_method='bank_transfer'
                )

                # Get or create recipient
                recipient_code = getattr(employee, 'paystack_recipient_code', None)
                if not recipient_code:
                    recipient_result = paystack.create_recipient(
                        name=employee.name,
                        account_number=employee.account_number,
                        bank_code=bank_code
                    )
                    if not recipient_result.get('status'):
                        payment.status = 'failed'
                        payment.save()
                        errors.append(
                            f"{employee.name}: recipient creation failed - "
                            f"{recipient_result.get('message')}"
                        )
                        continue

                    recipient_code = recipient_result['recipient_code']
                    if hasattr(employee, 'paystack_recipient_code'):
                        employee.paystack_recipient_code = recipient_code
                        employee.save(update_fields=['paystack_recipient_code'])

                transfers_payload.append({
                    "amount": int(net_amount * 100),
                    "recipient": recipient_code,
                    "reference": payment.transaction_reference,
                    "reason": f"Salary - {employee.name} ({employee.employee_id})"
                })

                payments_created.append({
                    'employee_id': employee.employee_id,
                    'employee_name': employee.name,
                    'bank': f"{employee.bank_name} - {employee.account_number}",
                    'net_salary': float(net_amount),
                    'reference': payment.transaction_reference,
                })

            except Employee.DoesNotExist:
                errors.append(f"Employee ID {emp_id} not found or not active")
            except Exception as e:
                errors.append(f"Error for employee ID {emp_id}: {str(e)}")

        # Fire bulk transfer in one API call
        if transfers_payload:
            bulk_result = paystack.bulk_transfer(transfers_payload)
            if not bulk_result.get('status'):
                logger.error(f"Bulk transfer API error: {bulk_result.get('message')}")
                errors.append(f"Bulk transfer error: {bulk_result.get('message')}")

        return Response({
            'message': f'Initiated {len(payments_created)} salary transfers',
            'total_amount': total_amount,
            'total_employees': len(payments_created),
            'payments': payments_created,
            'errors': errors,
            'note': 'Payments will be confirmed automatically via webhook'
        })

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def verify_payment(self, request):
        """
        UPDATED: Uses safer data extraction.
        For transfers, webhook handles completion automatically.
        This endpoint is a manual fallback check.
        """
        reference = request.data.get('reference')
        otp_code = request.data.get('otp')

        if not reference:
            return Response({'error': 'Reference required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payment = Payment.objects.get(transaction_reference=reference)

            # OTP verification (kept for collection payments)
            if otp_code:
                try:
                    otp = OTP.objects.get(reference=reference, code=otp_code, is_used=False)
                    if otp.failed_attempts >= 3:
                        raise ValidationError('Too many failed OTP attempts. Request a new OTP.')
                    if otp.has_expired():
                        return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)
                    if otp.code != otp_code:
                        otp.failed_attempts += 1
                        otp.save()
                        raise ValidationError('Incorrect OTP')
                    otp.is_used = True
                    otp.save()
                except OTP.DoesNotExist:
                    return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

            # If already completed by webhook, just return success
            if payment.status == 'completed':
                return Response({'message': 'Payment already verified and completed'})

            paystack = PaystackAPI()

            # For bank transfers use verify_transfer, for card use verify_transaction
            if payment.payment_method == 'bank_transfer':
                verification = paystack.verify_transfer(reference)
                transfer_data = verification.get('data') if isinstance(verification.get('data'), dict) else {}
                transfer_status = transfer_data.get('status', '')

                if verification.get('status') is True and transfer_status == 'success':
                    with transaction.atomic():
                        payment.status = 'completed'
                        payment.paystack_reference = str(transfer_data.get('id', ''))
                        payment.save()

                        Deduction.objects.filter(
                            employee=payment.employee, status='pending'
                        ).update(status='applied')

                        Notification.objects.create(
                            user=payment.employee.user,
                            message=f"Salary payment of ₦{payment.net_amount:,.2f} confirmed.",
                            type='success'
                        )

                    logger.info(f"Transfer manually verified for {payment.employee.name}")
                    return Response({'message': 'Payment verified successfully'})

                return Response(
                    {'error': f'Transfer not yet completed. Status: {transfer_status}'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            else:
                # Card payment via initialize_transaction
                verification = paystack.verify_transaction(reference)

                # FIXED: Safe data extraction
                paystack_status = (
                    verification.get('data', {}).get('status')
                    if isinstance(verification.get('data'), dict)
                    else None
                )

                if verification.get('status') is True and paystack_status == 'success':
                    with transaction.atomic():
                        payment.status = 'completed'
                        payment.paystack_reference = verification['data'].get('reference', '')
                        payment.save()

                        Deduction.objects.filter(
                            employee=payment.employee, status='pending'
                        ).update(status='applied')

                        Notification.objects.create(
                            user=payment.employee.user,
                            message=(
                                f"Payment credited for {payment.employee.employee_id} - "
                                f"{payment.employee.name}: ₦{payment.net_amount}"
                            ),
                            type='success'
                        )

                    logger.info(f"Payment verified for {payment.employee.name}")
                    return Response({'message': 'Payment verified successfully'})

                payment.status = 'failed'
                payment.save()
                return Response(
                    {'error': 'Payment verification failed'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        except Payment.DoesNotExist:
            return Response({'error': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def resend_otp(self, request):
        reference = request.data.get('reference')
        if not reference:
            return Response({'error': 'Reference required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            payment = Payment.objects.get(transaction_reference=reference)

            if not payment.employee.email:
                return Response({'error': 'Employee has no email'}, status=status.HTTP_400_BAD_REQUEST)

            otp_code = ''.join(random.choices(string.digits, k=6))
            OTP.objects.create(
                email=payment.employee.email,
                code=otp_code,
                reference=reference,
                expires_at=timezone.now() + timezone.timedelta(minutes=5)
            )

            try:
                send_mail(
                    'Payment Verification OTP - Resent',
                    f'Your new OTP for payment verification is: {otp_code}\n\nExpires in 5 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [payment.employee.email],
                    fail_silently=False,
                )
                return Response({'message': 'OTP sent successfully'})
            except Exception as e:
                logger.error(f"Failed to send OTP email: {e}")
                return Response({'error': 'Failed to send OTP'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Payment.DoesNotExist:
            return Response({'error': 'Payment not found'}, status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def generate_payslip(self, request):
        employee_id = request.data.get('employee_id')
        month = request.data.get('month')

        if not employee_id or not month:
            return Response(
                {'error': 'employee_id and month are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            employee = Employee.objects.get(id=employee_id)
        except Employee.DoesNotExist:
            return Response({'error': 'Employee not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            year, month_num = map(int, month.split('-'))
            from calendar import monthrange
            last_day = monthrange(year, month_num)[1]
            start_date = f"{year}-{month_num:02d}-01"
            end_date = f"{year}-{month_num:02d}-{last_day}"
        except Exception:
            return Response(
                {'error': 'Invalid month format. Use YYYY-MM'},
                status=status.HTTP_400_BAD_REQUEST
            )

        month_deductions = Deduction.objects.filter(
            employee=employee, date__range=[start_date, end_date]
        )
        total_deductions = month_deductions.aggregate(Sum('amount'))['amount__sum'] or 0
        net_salary = employee.salary - total_deductions

        month_payments = Payment.objects.filter(
            employee=employee,
            payment_date__range=[start_date, end_date],
            status='completed'
        )

        payslip_data = {
            'employee': {
                'name': employee.name,
                'employee_id': employee.employee_id,
                'type': employee.type,
                'location': employee.location,
                'bank_name': employee.bank_name,
                'account_number': employee.account_number,
            },
            'month': month,
            'earnings': {
                'base_salary': float(employee.salary),
                'allowances': 0,
                'gross_salary': float(employee.salary)
            },
            'deductions': {
                'total': float(total_deductions),
                'items': [
                    {
                        'date': d.date.isoformat(),
                        'amount': float(d.amount),
                        'reason': d.reason,
                        'status': d.status
                    } for d in month_deductions
                ]
            },
            'net_salary': float(net_salary),
            'payment_status': 'Paid' if month_payments.exists() else 'Pending',
            'generated_at': timezone.now().isoformat()
        }

        payslip_html = f"""
        <div class="payslip-container" style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; border: 2px solid #333;">
            <div class="header" style="text-align: center; border-bottom: 2px solid #117e62; padding-bottom: 20px; margin-bottom: 30px;">
                <h1 style="color: #117e62; margin: 0;">FOTASCO SECURITY SERVICES</h1>
                <h2 style="margin: 10px 0;">PAYSLIP</h2>
                <p style="margin: 5px 0;">Month: {month}</p>
            </div>
            <div class="employee-info" style="margin-bottom: 30px;">
                <h3 style="color: #117e62; border-bottom: 1px solid #ccc;">Employee Information</h3>
                <table style="width: 100%;">
                    <tr><td><strong>Name:</strong></td><td>{employee.name}</td></tr>
                    <tr><td><strong>Employee ID:</strong></td><td>{employee.employee_id}</td></tr>
                    <tr><td><strong>Type:</strong></td><td>{employee.type.title()}</td></tr>
                    <tr><td><strong>Location:</strong></td><td>{employee.location}</td></tr>
                    <tr><td><strong>Bank:</strong></td><td>{employee.bank_name}</td></tr>
                    <tr><td><strong>Account:</strong></td><td>{employee.account_number}</td></tr>
                </table>
            </div>
            <div class="earnings" style="margin-bottom: 30px;">
                <h3 style="color: #117e62; border-bottom: 1px solid #ccc;">Earnings</h3>
                <table style="width: 100%;">
                    <tr><td>Base Salary</td><td style="text-align: right;">₦{employee.salary:,.2f}</td></tr>
                    <tr style="font-weight: bold; font-size: 1.2em;"><td>Net Salary</td><td style="text-align: right;">₦{net_salary:,.2f}</td></tr>
                </table>
            </div>
            <div class="deductions" style="margin-bottom: 30px;">
                <h3 style="color: #117e62; border-bottom: 1px solid #ccc;">Deductions</h3>
                <table style="width: 100%;">
                    {"".join([f"<tr><td>{d.reason} ({d.date})</td><td style='text-align: right;'>₦{d.amount:,.2f}</td></tr>" for d in month_deductions])}
                    <tr style="font-weight: bold;"><td>Total Deductions</td><td style="text-align: right;">₦{total_deductions:,.2f}</td></tr>
                </table>
            </div>
            <div class="footer" style="margin-top: 50px; text-align: center; font-size: 0.9em; color: #666;">
                <p>Generated on {timezone.now().strftime('%Y-%m-%d %H:%M')}</p>
                <p>This is a computer-generated document and does not require signature.</p>
            </div>
        </div>
        """

        return Response({'payslip_data': payslip_data, 'payslip_html': payslip_html})

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.status == "completed":
            return Response(
                {"error": "Completed payments cannot be modified"},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().update(request, *args, **kwargs)


# ─────────────────────────────────────────
# DEDUCTION VIEWSET
# ─────────────────────────────────────────

class DeductionViewSet(viewsets.ModelViewSet):
    queryset = Deduction.objects.all().order_by('id')
    serializer_class = DeductionSerializer
    filterset_fields = ["employee", "status", "date"]

    def get_permissions(self):
        if self.action in ["create", "update", "partial_update", "destroy"]:
            return [IsAuthenticated(), IsDeductionAdmin()]
        return [IsAuthenticated()]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == 'admin' or getattr(user, "is_deduction_admin", False):
            return Deduction.objects.all().order_by('id')
        if user.role in ["staff", "guard"]:
            return Deduction.objects.filter(employee__user=user).order_by('id')
        return Deduction.objects.none()

    def perform_create(self, serializer):
        deduction = serializer.save()
        Notification.objects.create(
            user=deduction.employee.user,
            message=(
                f"Deduction added for {deduction.employee.employee_id} - "
                f"{deduction.employee.name}: ₦{deduction.amount}. Reason: {deduction.reason}"
            ),
            type='warning'
        )

    @action(detail=True, methods=['put'], permission_classes=[IsAuthenticated, IsDeductionAdmin])
    def update_status(self, request, pk=None):
        deduction = self.get_object()
        new_status = request.data.get('status')

        if new_status not in ['pending', 'applied', 'cancelled', 'terminated']:
            return Response(
                {'error': 'Invalid status. Must be: pending, applied, cancelled, or terminated'},
                status=status.HTTP_400_BAD_REQUEST
            )

        deduction.status = new_status
        deduction.save()

        Notification.objects.create(
            user=deduction.employee.user,
            message=f"Deduction status updated to {new_status} for ₦{deduction.amount}. Reason: {deduction.reason}",
            type='info' if new_status == 'applied' else 'warning'
        )

        return Response({
            'message': f'Deduction status updated to {new_status}',
            'deduction': DeductionSerializer(deduction).data
        })


# ─────────────────────────────────────────
# SACKED EMPLOYEE VIEWSET
# ─────────────────────────────────────────

class SackedEmployeeViewSet(viewsets.ModelViewSet):
    queryset = SackedEmployee.objects.all().order_by('id')
    serializer_class = SackedEmployeeSerializer

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsAuthenticated(), IsSackAdmin()]
        return [IsAuthenticated()]

    @action(detail=True, methods=['post'], permission_classes=[IsAuthenticated, IsSackAdmin])
    def reinstate(self, request, pk=None):
        sacked_record = self.get_object()
        employee = sacked_record.employee

        with transaction.atomic():
            employee.status = 'active'
            employee.save()
            sacked_record.delete()

            Notification.objects.create(
                user=employee.user,
                message=f"Employee {employee.employee_id} - {employee.name} has been reinstated.",
                type='success'
            )
            logger.info(f"{request.user.username} reinstated {employee.name}")

        return Response({'message': 'Employee reinstated successfully'})


# ─────────────────────────────────────────
# NOTIFICATION VIEWSET
# ─────────────────────────────────────────

class NotificationViewSet(viewsets.ModelViewSet):
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated, CanEditNotification]
    queryset = Notification.objects.all().order_by('id')

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == 'admin' or getattr(user, 'is_notification_admin', False):
            return Notification.objects.all().order_by('id')
        return Notification.objects.filter(user=user).order_by('id')

    @action(detail=False, methods=['post'])
    def mark_all_read(self, request):
        self.get_queryset().update(is_read=True)
        return Response({'message': 'All notifications marked as read'})


# ─────────────────────────────────────────
# COMPANY VIEWSET
# ─────────────────────────────────────────

class CompanyViewSet(viewsets.ModelViewSet):
    queryset = Company.objects.all().order_by('id')
    serializer_class = CompanySerializer
    permission_classes = [CanViewAndEditCompany]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.role == 'admin':
            return Company.objects.all().order_by('id')
        if user.role in ['staff', 'guard']:
            return Company.objects.filter(
                assigned_guards__user=user
            ).distinct().order_by('id')
        return Company.objects.none()


def frontend(request):
    return render(request, "frontend/index.html")
