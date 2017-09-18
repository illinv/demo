# coding=utf8
from __future__ import unicode_literals

from rest_framework import status, views, generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework.parsers import FormParser, MultiPartParser

from django.http import Http404
from django.contrib.auth import authenticate, login, logout
from django.utils.http import urlsafe_base64_decode
from django.core.exceptions import ValidationError
from rest_framework.decorators import detail_route
from django.contrib.auth.password_validation import validate_password

from models import (Profile, AuthorizingDocuments, PersonalDocumentation, User as CustomUser)
from serializers import (ProfileETSerializer, ProfileLESerializer,
                         ProfilePPSerializer, AuthDocSerializer,
                         CustomUserSerializer, SubscriptionSerializer,
                         PersonalDocSerializer)

from tenders.serializers import (ProfileShortInfoCustomerSerializer,
                                 ProfileShortInfoOperatorSerializer)
from custom_permissions import OperatorPermission, IsAdminOrIsSelf
from tasks import (notification_reset_password_task,
                   notification_change_password_task)
from tenders.processors import password_reset_token_generator, normalize_email
from sendfile import sendfile
from django.shortcuts import get_object_or_404
from tenders.processors import Notification
from tenders.models import Order
from django.conf import settings


class PersonalDataView(views.APIView):
    permission_classes = (IsAdminOrIsSelf,)

    def get_object(self, request):
        user = request.user
        profile = Profile.objects.by_user(user)
        requisites_pp = profile.requisites_pp
        documents = PersonalDocumentation.objects.filter(requisites_pp=requisites_pp)
        return documents

    def get(self, request, format=None):
        documents = self.get_object(request)
        serializer = PersonalDocSerializer(documents, many=True)
        return Response(data=serializer.data, status=status.HTTP_200_OK)


class PersonalDocCreateAPIView(generics.CreateAPIView):
    queryset = PersonalDocumentation.objects.all()
    serializer_class = PersonalDocSerializer
    permission_classes = [IsAdminOrIsSelf, ]
    parser_classes = (MultiPartParser, FormParser, )

    def perform_create(self, serializer, format=None):
        user = self.request.user
        profile = Profile.objects.by_user(user)
        requisites_pp = profile.requisites_pp
        if self.request.data.get('passport_scan') is not None:
            passport_scan = self.request.data.get('passport_scan')
            serializer.save(requisites_pp=requisites_pp, passport_scan=passport_scan)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PersonalDocDestoryAPIView(generics.DestroyAPIView):
    queryset = PersonalDocumentation.objects.all()

    def get(self, request, format=None, pk=None):
        documents = PersonalDocumentation.objects.filter(pk=pk)
        serializer = PersonalDocSerializer(documents, many=True)
        return Response(serializer.data)

    def delete(self, request, pk=None):
        document = self.get_object()
        document.delete()
        return Response(status=status.HTTP_200_OK)


class AuthDocView(views.APIView):

    permission_classes = (IsAuthenticated, OperatorPermission,)

    DOCUMENT_TYPE_LIST = [i[0] for i in AuthorizingDocuments.TYPE]

    def create_object(self, profile, type_document):
        if int(type_document) in self.DOCUMENT_TYPE_LIST:
            return profile.auth_doc.create(type=type_document)
        else:
            raise Http404

    def get_or_create_object(self, request, type_document):
        user = request.user
        profile = Profile.objects.by_user(user)
        try:
            return profile.auth_doc.filter(type=type_document)[0]
        except IndexError:
            return self.create_object(profile, type_document)

    def get_object(self, request):
        user = request.user
        profile = Profile.objects.by_user(user)
        return profile.auth_doc

    def get(self, request, format=None):
        documents = self.get_object(request)
        serializer = AuthDocSerializer(documents, many=True)
        return Response(data=serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, format=None):
        type_document = request.data.get('type', -1)
        document = self.get_or_create_object(request, type_document)
        document.status = AuthorizingDocuments.VERIFICATION
        serializer = AuthDocSerializer(document, data=request.data,
                                       partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfileMixin(views.APIView):

    SERIALIZER_SET = {
        Profile.PHYSICAL_PERSON: ProfilePPSerializer,
        Profile.ENTREPRENEUR: ProfileETSerializer,
        Profile.LEGAL_ENTITY: ProfileLESerializer
    }

    def get_object(self, request):
        user = request.user
        try:
            return Profile.objects.by_user(user)
        except Profile.DoesNotExist:
            raise Http404

    def get_serializer_class(self, organization):
        return self.SERIALIZER_SET[organization]


class ProfileView(ProfileMixin):

    def get(self, request, format=None):
        profile = self.get_object(request)
        organization = profile.organization
        serializer = self.get_serializer_class(organization)(profile)
        return Response(serializer.data)

    def patch(self, request, format=None):
        profile = self.get_object(request)
        organization = profile.organization
        serializer = self.get_serializer_class(organization)(
            profile, data=request.data
        )

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):
        user = request.user
        ogn = request.data.get('organization')
        role = request.data.get('role')

        try:
            _ = user.profile
            return Response({'Error': 'Profile exists.'},
                            status=status.HTTP_400_BAD_REQUEST)
        except Profile.DoesNotExist:
            pass

        if role == Profile.OPERATOR and ogn == Profile.PHYSICAL_PERSON:
            return Response({'Error': 'Organization incorrect.'},
                            status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer_class(ogn)(
            data=request.data,
            context={'request': request}
        )

        if serializer.is_valid():
            additional_data = {
                'user': user,
                'role': role,
                'organization': ogn
            }

            serializer.save(**additional_data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfileSubscriptionView(ProfileMixin):
    def get(self, request, format=None):
        profile = self.get_object(request)
        serializer = SubscriptionSerializer(profile.subscription)
        return Response(serializer.data)


class ProfileShortInfoMixin(views.APIView):
    SERIALIZER_SET = {
        Profile.CUSTOMER: ProfileShortInfoCustomerSerializer,
        Profile.OPERATOR: ProfileShortInfoOperatorSerializer
    }

    NUMBER_NOTIFICATION = 16

    def get_data(self, request):
        profile = self._get_profile(request)

        if profile.role == Profile.OPERATOR:
            context = self._get_context_operator(request)

        elif profile.role == Profile.CUSTOMER:
            context = self._get_context_customer(request)

        data = {
            'profile': profile,
            'context': context
        }

        return data


    def get_serializer_class(self, role):
        return self.SERIALIZER_SET[role]

    def _get_context_customer(self, request):
        DONE = 'DN'
        IN_WORK = 'WK'
        OPEN = 'OP'
        number_notification = self._get_number_notification()
        context = {
            'number_notification': number_notification,
            'orders_dn': self._get_count_orders(request, status=DONE, role="CU"),
            'orders_wk': self._get_count_orders(request, status=IN_WORK, role="CU"),
            'orders_op': self._get_count_orders(request, status=OPEN, role="CU"),

        }
        return context

    def _get_context_operator(self, request):
        DONE = 'DN'
        IN_WORK = 'WK'
        number_notification = self._get_number_notification()
        context={
            'number_notification': number_notification,
            'orders_dn': self._get_count_orders(request, status=DONE, role="OP"),
            'orders_wk': self._get_count_orders(request, status=IN_WORK, role="OP"),
        }
        return context

    def _get_profile(self, request):
        user = request.user
        try:
            return Profile.objects.by_user(user)

        except Profile.DoesNotExist:
            raise Http404

    def _get_count_orders(self, request, status, role):
        if role == Profile.OPERATOR:
            orders = Order.objects.by_operator(request.user).filter(status=status)
        elif role == Profile.CUSTOMER:
            orders = Order.objects.by_customer(request.user).filter(status=status)
        return orders.count()

    def _get_number_notification(self):
        return self.NUMBER_NOTIFICATION

    def _get_count_tenders(self):
        pass


class ProfileBaseInfoView(ProfileShortInfoMixin):
    def get(self, request, format=None):
        data = self.get_data(request)
        profile = data['profile']
        context = data['context']
        serializer = self.get_serializer_class(profile.role)(profile, context=context)
        return Response(serializer.data)


class LogoutView(views.APIView):
    permission_classes = (AllowAny,)

    def get(self, request, format=None):
        logout(request)
        return Response(status=status.HTTP_200_OK)


class LoginView(ProfileMixin):
    permission_classes = (AllowAny,)

    REMEMBER_ME = 'RM'

    def post(self, request, format=None):
        email = normalize_email(request.data.get('email', ''))
        password = request.data.get('password', '')
        remember_me = (request.data.get('remember_me', '') == self.REMEMBER_ME)
        if not remember_me:
            request.session.set_expiry(0)
        if request.user.is_authenticated:
            logout(request)
        user = authenticate(email=email, password=password)
        if not user:
            return Response("Email or password incorrect.",
                            status=status.HTTP_400_BAD_REQUEST)
        login(request, user)
        profile = self.get_object(request)
        serializer = self.get_serializer_class(profile.organization)(profile)
        return Response(serializer.data)


class UserView(ProfileMixin):
    permission_classes = (AllowAny,)

    def post(self, request, format=None):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            email = normalize_email(serializer.data['email'])
            password = serializer.data['password']
            CustomUser.objects.create_user(email, password)
            user = authenticate(email=email, password=password)
            login(request, user)
            serializer = CustomUserSerializer(user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailView(views.APIView):
    permission_classes = (AllowAny,)

    def post(self, request, format=None):
        email = normalize_email(request.data.get("email"))
        return Response(not CustomUser.objects.filter(email=email).exists())


class ChangePasswordView(views.APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, format=None):
        user = request.user
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")

        if user.check_password(old_password):

            try:
                validate_password(new_password, user=user)
            except ValidationError:
                return Response({"Error": {"error_type": "pwa",
                                           "error_text": "Пароль был использован Вами ранее. Пожалуйста, введите новый."}},
                                status=status.HTTP_400_BAD_REQUEST)

            user.set_password(new_password)
            user.save()
            login(request, user)
            notification_change_password_task.delay(
                user.email, Notification.template_password_change())
            return Response(status=status.HTTP_200_OK)
        else:
            return Response({"Error": {"error_type":"opi",
                                       "error_text":"Старый пароль не совпадает."}},
                            status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordRequestView(views.APIView):
    permission_classes = (AllowAny,)

    def post(self, request, format=None):
        email = normalize_email(request.data.get("email"))
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"Error": "Email not found"},
                            status=status.HTTP_400_BAD_REQUEST)
        domain = settings.DOMAIN
        notification_reset_password_task.delay(user.id, domain)
        return Response(status=status.HTTP_200_OK)


class PasswordResetConfirmView(views.APIView):
    permission_classes = (AllowAny,)

    def post(self, request, uidb64=None, token=None, *arg, **kwargs):
        assert uidb64 is not None and token is not None
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None
        if (user is not None and
                password_reset_token_generator.check_token(user, token)):
            new_password = request.data.get('new_password', None)
            self._set_password(user=user, new_password=new_password)
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(
                {"Error": "The reset password link is no longer valid"},
                status=status.HTTP_400_BAD_REQUEST
            )

    def _set_password(self, user=None, new_password=None):
        if new_password and user is not None:
            user.set_password(new_password)
            user.save()


class DownloadAuthDocView(views.APIView):
    permission_classes = (IsAdminUser, )

    def get(self, request, format=None, pk=None):
        auth_doc = get_object_or_404(AuthorizingDocuments, pk=pk)
        return sendfile(request, auth_doc.document.path, attachment=True)


class DownloadPersonalDocView(views.APIView):
    permission_classes = (IsAdminOrIsSelf, )

    def get(self, request, format=None, pk=None):
        personal_doc = get_object_or_404(PersonalDocumentation, pk=pk)
        return sendfile(request, personal_doc.passport_scan.path, attachment=True)
