from .models import UserProfile, Account
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver


@receiver(post_save, sender=Account)
def create_profile(sender, instance, created, **kwargs):
    if instance and created:

        user_profile = UserProfile.objects.create(user=instance)
        instance.profile = user_profile
        user_profile.save()
    else:
        try:
            user_profile = UserProfile.objects.get(user=instance)
            user_profile.save()
        except:
            UserProfile.objects.create(user=instance)
