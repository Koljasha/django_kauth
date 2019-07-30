# from django.db import models
from django.contrib.auth.models import AbstractUser

from django.db import models


class KauthUser(AbstractUser):
    email = models.EmailField(unique=True,
                              verbose_name='Адрес электронной почты',
                              help_text='Обязательное поле. Укажите корректный адрес электронной почты.',
                              error_messages={'unique': 'Пользователь с таким адресом электронной почты уже существует.'})
