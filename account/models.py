from django.db import models

# Create your models here.
from django.db import models

# Create your models here.
from django.db import models
from django.urls import reverse
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils.text import slugify
from django.contrib.auth.hashers import make_password
from django.dispatch import receiver
from django.db.models.signals import post_save, pre_save
# from .validators import UnicodeUsernameValidators

# Create your models here.


class MyAccountManager(BaseUserManager):
    def create_user(self, first_name, last_name, username, email, password=None):
        if not username:
            raise ValueError("User must have a username")
        if not email:
            raise ValueError("User must have an email address")
        user = self.model(username=username, first_name=first_name,
                          last_name=last_name, email=self.normalize_email(email))
        # user.password = make_password(password)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, first_name, last_name, username, email, password):
        user = self.create_user(first_name=first_name, last_name=last_name,
                                username=username, email=self.normalize_email(email), password=password)
        user.is_admin = True
        user.is_staff = True
        user.is_superadmin = True
        user.is_active = True
        user.save(using=self._db)

        return user


class Account(AbstractBaseUser):

    # username_validator = UnicodeUsernameValidators
    first_name = models.CharField(max_length=50)
    username = models.CharField(max_length=50, unique=True, db_index=True)
    last_name = models.CharField(max_length=50)
    # phone_number = models.IntegerField(null=True)
    email = models.EmailField(max_length=100, unique=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    is_admin = models.BooleanField(default=False)
    is_superadmin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ["first_name", "last_name", "username", ]
    objects = MyAccountManager()

    def has_perm(self, perm, obj=None):
        return self.is_admin

    def has_module_perms(self, add_module):
        return True

    def __str__(self) -> str:
        return self.first_name


class UserProfile(models.Model):

    user = models.OneToOneField(
        Account, on_delete=models.CASCADE, related_name="profile", blank=True, null=True)
    bio = models.CharField(max_length=100, null=True, blank=True)
    image = models.ImageField(
        upload_to="profile/profile_photo", default=None, blank=True)
    phone_number = models.CharField(max_length=15, null=True, blank=True)

    # def get_absolute_url(self):
    #     return reverse("profile", kwargs={"pk": self.pk})

    def __str__(self) -> str:
        return self.user.username

    def get_image(self, obj):
        if obj.image:
            return obj.image.url

        return 'https://static.productionready.io/images/smiley-cyrus.jpg'
