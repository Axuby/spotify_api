

import jwt
from account.api.serializers import RegisterationSerializer
from account.api.utils import Utils
from account.models import Account, UserProfile
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from django.contrib.sites.shortcuts import get_current_site


from django.shortcuts import render
from django.urls import reverse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import JsonResponse

from room.models import Room
from .serializers import LoginSerializer, ProfileSerializer, RegisterationSerializer, ChangePasswordSerializer, UpdateUserSerializer, VerifyEmailSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import generics, status
from django.contrib.auth.models import User
from django.conf import settings
from rest_framework.permissions import AllowAny, IsAuthenticated
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
# Create your views here.


class LogoutView(APIView):

    def post(self, request, *args, **kwargs):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer


class ChangePasswordView(generics.UpdateAPIView):

    queryset = Account.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

    # def get_object(self, queryset=None):
    #     obj = self.request.user
    #     return obj

    # def update(self, request, *args, **kwargs):
    #     self.object = self.get_object()
    #     serializer = self.get_serializer(data=request.data)

    #     if serializer.is_valid():
    #         # Check old password
    #         if not self.object.check_password(serializer.data.get("old_password")):
    #             return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
    #         # set_password also hashes the password that the user will get
    #         self.object.set_password(serializer.data.get("new_password"))
    #         self.object.save()
    #         response = {
    #             'status': 'success',
    #             'code': status.HTTP_200_OK,
    #             'message': 'Password updated successfully',
    #             'data': []
    #         }

    #         return Response(response)

    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UpdateProfileView(generics.UpdateAPIView):

    queryset = Account.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = UpdateUserSerializer


class GetRouteAV(APIView):
    def get(self, request):
        routes = [
            '/api/login/',
            '/api/register/',
            '/api/token/refresh/'
        ]
        return Response(routes)


class RegistrationView(generics.CreateAPIView):
    serializer_class = RegisterationSerializer

    def post(self, request, *args, **kwargs):
        serializer = RegisterationSerializer(data=request.data)
        data = {}
        if serializer.is_valid():
            username = serializer.validated_data.get("username")
            first_name = serializer.validated_data.get("first_name")
            last_name = serializer.validated_data.get("last_name")
            email = serializer.validated_data.get("email")
            password = serializer.validated_data.get("password")
            # confirm_password = serializer.validated_data.get("password2")
            account = Account.objects.create_user(
                first_name=first_name, last_name=last_name, username=username, email=email, password=password)
            data["status"] = "success"
            data["username"] = account.username
            data["email"] = account.email
            refresh_token = RefreshToken.for_user(account)
            data["refresh_token"] = str(refresh_token)
            data["access_token"] = str(refresh_token.access_token)

            current_site = get_current_site(request).domain
            relative_path = reverse("verify-email")
            abs_url = "http://" + current_site + relative_path + \
                "?token=" + str(refresh_token.access_token)

            mail_subject = "Please activate your Account"
            message = "Hi" + username + "," + \
                " Please Use the Link below to activate your account:" + "" + abs_url

            Utils.send_email(mail_subject, message, email)
            return Response(data, status=status.HTTP_201_CREATED)
        data["error"] = serializer.errors
        data["status"] = "success"
        return Response(data, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(APIView):
    # serializer_class = VerifyEmailSerializer
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description="Description", type=openapi.TYPE_STRING)

    @ swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request, *args, **kwargs):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, secret_key=settings.SECRET_KEY)
            account = Account.objects.get(id=payload.get('user_id'))

            if not account.is_active:
                account.is_active = True
                account.save()
                return Response({
                    "message": " Account Successfully activated!",
                    "status": "success",
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "message": " Account already activated!",
                    "status": "success",
                }, status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as e:
            print(e)
            return Response({"error": f"Activation expired:{e}", "status": "fail", }, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as e:
            return Response({"error": f"Invalid token: {e}", "status": "success", }, status=status.HTTP_400_BAD_REQUEST)


class ProfileRetrieveAPIView(generics.RetrieveAPIView):
    permission_classes = (AllowAny,)
    queryset = UserProfile.objects.all()
    # renderer_classes = (ProfileJSONRenderer,)
    serializer_class = ProfileSerializer

    def retrieve(self, request, pk, *args, **kwargs):
        try:
            profile = UserProfile.objects.select_related('user').get(
                user__pk=pk
            )
            print(profile)

        except UserProfile.DoesNotExist as e:
            print("Error", e)

        serializer = self.serializer_class(profile, data=request.data)
        if serializer.is_valid():
            profile = serializer.validated_data.get('userprofile', {})

        print(profile.user.email)
        data = {
            "username": profile.user.username,
            "bio": profile.bio,
            "image":  profile.image if profile.image else "",
            "status": "success",
        }

        return Response(data, status=status.HTTP_200_OK)


class UserRetrieveUpdateAPIView(generics.RetrieveUpdateAPIView):
    permission_classes = (IsAuthenticated,)
    # renderer_classes = (UserJSONRenderer,)
    serializer_class = RegisterationSerializer

    def retrieve(self, request, *args, **kwargs):
        # There is nothing to validate or save here. Instead, we just want the
        # serializer to handle turning our `User` object into something that
        # can be JSONified and sent to the client.
        serializer = self.serializer_class(request.user)

        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        serializer_data = request.data.get('user', {})
        user_data = request.data.get('user', {})

#         serializer_data = {’username': user_data.get('username', request.user.username),
#     ’email': user_data.get('email', request.user.email),
# ’profile': {
#            ’bio': user_data.get('bio', request.user.profile.bio),
#             ’image': user_data.get('image', request.user.profile.image)
#     }

        # Here is that serialize, validate, save pattern we talked about
        # before.
        serializer = self.serializer_class(
            request.user, data=serializer_data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)
