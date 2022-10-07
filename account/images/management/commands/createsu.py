from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from ....models import Account


class Command(BaseCommand):
    help = 'Creates a superuser.'

    def handle(self, *args, **options):
        if not Account.objects.filter(username='admin').exists():
            Account.objects.create_superuser(
                first_name="admin",
                last_name="admin",
                username='admin',
                password='adminadmin'
            )
