from django.utils.html import format_html
from django.contrib.auth.admin import UserAdmin
from .models import Account, UserProfile
from django.contrib import admin


# Register your models here.
class UserProfileAdmin(admin.StackedInline):
    list_display = ["location", "phone_number"]
    model = UserProfile


class AccountAdmin(UserAdmin):
    list_display = ['first_name', 'last_name', 'username',
                    'email', 'last_login', 'date_joined', 'is_active']
    list_display_links = ['first_name', 'last_name']
    readonly_fields = ['last_login', 'date_joined', ]
    ordering = ['-date_joined']

    filter_horizontal = ()
    fieldsets = ()
    list_filter = ()
    inlines = [UserProfileAdmin]


# Register your models here.
admin.site.register(Account, AccountAdmin)
