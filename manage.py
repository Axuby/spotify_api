#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'spotify_api.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()


# container_commands:
#         01_migrate:
#             command:"django-admin.py migrate"
#             leader_only:true
#         02_createsuperuser:
#             command:"echo \"from account.models import Account; Account.objects.create_superuser(first_name=admin,last_name=admin,username=admin,email=azubuinsamuel@gmail.com,password=adminadmin)\" | python manage.py runserver"
#             leader_only:true
# option_settings:
#         aws:elasticbeanstalk:application:environment:
#             DJANGO_SETTINGS_MODULE: spotify_api.settings

# container_commands:
#   01_makemigrations:
#     command: "source /var/app/venv/*/bin/activate && python3 manage.py makemigrations --noinput"
#     leader_only: true
#   02_migrate:
#     command: "source /var/app/venv/*/bin/activate && python3 manage.py migrate --noinput"
#     leader_only: true
#   03_createsu:
#     command: "source /var/app/venv/*/bin/activate && python3 account/manage.py createsu"
#   04_collectstatic:
#     command: "source /var/app/venv/*/bin/activate && python3 manage.py collectstatic --noinput"
#     leader_only: true
#   option_settings:
#       aws: elasticbeanstalk: application: environment:
#           DJANGO_SETTINGS_MODULE: spotify_api.settings
