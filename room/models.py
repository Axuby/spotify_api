from email.policy import default
from django.db import models
import random
import string

# Create your models here.


def generate_code():
    length = 6
    while True:
        code = "".join(random.choices(string.ascii_uppercase, k=length))
        if Room.objects.filter(code=code).count() == 0:
            return code

class Room(models.Model):
    code = models.CharField(max_length=20, default=generate_code)

    def __str__(self) -> str:
        return super().__str__()



