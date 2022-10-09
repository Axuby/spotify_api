

from base64 import urlsafe_b64decode
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.translation import gettext_lazy as _
from account.models import Account, UserProfile
from rest_framework import HTTP_HEADER_ENCODING, authentication
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from rest_framework_simplejwt.exceptions import AuthenticationFailed


class LoginSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Add custom claims
        token['username'] = user.username
        token['email'] = user.email
        # ...
        return token


class ResetPasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = Account
        fields = ('email',)
        extra_kwargs = {
            "email": {
                "write_only": True
            }
        }

    def validate_email(self, value):
        lower_email = value.lower()

        return lower_email


class SetNewPasswordSerializer(serializers.Serializer):
    token = serializers.CharField(min_length=1, write_only=True)
    uuidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        model = Account
        fields = ("password", "confirm_password", "token", "uuidb64")

    def validate(self, attrs):
        try:
            if attrs.get('password') != attrs.get('confirm_password'):
                raise serializers.ValidationError(
                    {"password": "Password fields didn't match."})
            token = attrs.get('token')
            uuidb64 = attrs.get('uuidb64')

            id = force_str(urlsafe_base64_decode(uuidb64))
            account = Account.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(account, token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            account.set_password(attrs.get('password'))
            account.save()
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)


class RegisterationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Account
        fields = ('username', "first_name", "last_name",
                  'email', 'password', 'confirm_password')

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})

        return attrs

    def validate_email(self, value):
        lower_email = value.lower()
        if Account.objects.filter(email__iexact=lower_email).exists():
            raise serializers.ValidationError("Email already in use")
        return lower_email

    # def create(self, validated_data):
    #     account = Account.objects.create_user(
    #         username=validated_data.get('username'), email=validated_data.get('email'), password=validated_data.get('password'), first_name=validated_data.get('first_name'), last_name=validated_data.get('last_name'))

    #     refresh_token = RefreshToken.for_user(account)
    #     account["refresh_token"] = str(refresh_token)
    #     account["access_token"] = str(refresh_token.access_token)
    #     return account
    def update(self, instance, validated_data):
        password = validated_data.pop("password", None)
        account = super().update(instance, validated_data)
        if password is not None:
            account.set_password(password)
            account.save()
        return account


class ChangePasswordSerializer(serializers.ModelSerializer):
    new_password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Account
        fields = ('old_password', 'new_password', 'confirm_password')

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})

        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError(
                {"old_password": "Old password is not correct"})
        return value

    def update(self, instance, validated_data):

        instance.set_password(validated_data.get('new_password'))
        instance.save()

        return instance


class ProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username')
    bio = serializers.CharField(allow_blank=True, required=False)
    image = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = ('username', 'bio', 'image',)
        read_only_fields = ('username',)

    def get_image(self, obj):
        if obj.image:
            return obj.image.url

        return 'https://static.productionready.io/images/smiley-cyrus.jpg'


class UpdateUserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(write_only=True)
    email = serializers.EmailField(required=True)
    bio = serializers.CharField(source='profile.bio', read_only=True)
    image = serializers.CharField(source='profile.image', read_only=True)

    class Meta:
        model = Account
        fields = ('username', 'first_name', 'last_name',
                  'email', 'bio', 'image', 'profile')
        # extra_kwargs = {
        #     'first_name': {'required': True},
        #     'last_name': {'required': True},
        # }

    def validate_email(self, value):
        user = self.context.get('request').user
        if Account.objects.exclude(pk=user.pk).filter(email__iexact=value).exists():
            raise serializers.ValidationError(
                {"email": "This email is already in use."})
        return value

    def validate_username(self, value):
        user = self.context('request').user
        if Account.objects.exclude(pk=user.pk).filter(username__iexact=value).exists():
            raise serializers.ValidationError(
                {"username": "This username is already in use."})
        return value

    def update(self, instance, validated_data):
        profile = validated_data.pop('profile', {})

        user = self.context.get('request').user
        if user.pk != instance.pk:
            raise serializers.ValidationError(
                {"authorize": "You dont have permission to access this user."})

        for (key, value) in validated_data.items():
            setattr(instance, key, value)
        instance.save()
        for (key, value) in profile.items():
            setattr(instance.profile, key, value)
        instance.profile.save()

        return instance


class VerifyEmailSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=100)

    class Meta:
        model = Account
        fields = ('token',)
