from django import forms

from django.contrib.auth import authenticate
from django.core.validators import validate_email

from django.core import signing

from django.core.exceptions import ValidationError, ObjectDoesNotExist

from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from django.contrib.auth.hashers import check_password
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import AuthenticationForm, UsernameField

from .models import KauthUser
from .utilities import kauth_send_mail


class KauthAuthenticationForm(AuthenticationForm):
    username = UsernameField(label='Имя пользователя / Адрес электронной почты', widget=forms.TextInput(attrs={'autofocus': True}))

    def clean(self):
        username = self.cleaned_data['username']
        try:
            validate_email(username)
        except ValidationError:
            pass
        else:
            try:
                user = KauthUser.objects.get(email=username)
            except ObjectDoesNotExist:
                pass
            else:
                username = user.username

        password = self.cleaned_data.get('password')

        if username is not None and password:
            self.user_cache = authenticate(self.request, username=username, password=password)
            if self.user_cache is None:
                raise self.get_invalid_login_error()
            else:
                self.confirm_login_allowed(self.user_cache)

        return self.cleaned_data


class KauthRegistrationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = KauthUser
        fields = ('username', 'email')

    def save(self, commit=True):
        user = super().save(commit=False)
        user.is_active = False
        if commit:
            user.save()

        self.sender['to_email'] = self.cleaned_data["email"]

        self.context['user'] = user
        self.context['email'] = self.cleaned_data["email"]
        self.context['uid'] = urlsafe_base64_encode(force_bytes(user.pk))
        self.context['token'] = signing.dumps(user.date_joined.timestamp())

        kauth_send_mail(**self.sender, context=self.context)

        return user


class KauthUserChangeForm(forms.ModelForm):
    password = forms.CharField(
        label="Пароль",
        strip=False,
        widget=forms.PasswordInput,
        help_text='Введите пароль для подтверждения изменений',
    )

    class Meta:
        model = KauthUser
        fields = ('username', 'first_name', 'last_name')

    def clean(self):
        super().clean()
        password = self.cleaned_data['password']
        if not check_password(password, self.instance.password):
            errors = {'password': ValidationError('Неверный пароль пользователя', code='invalid')}
            raise forms.ValidationError(errors)


class KauthEmailChangeForm(forms.ModelForm):
    password = forms.CharField(
        label="Пароль",
        strip=False,
        widget=forms.PasswordInput,
        help_text='Введите пароль для подтверждения изменений',
    )

    class Meta:
        model = KauthUser
        fields = ('email',)

    def clean(self):
        super().clean()
        password = self.cleaned_data['password']
        if not check_password(password, self.instance.password):
            errors = {'password': ValidationError('Неверный пароль пользователя', code='invalid')}
            raise forms.ValidationError(errors)

    def save(self, commit=True):
        user = super().save(commit=False)
        user.email = self.context['old_email']
        if commit:
            user.save()

        self.sender['to_email'] = self.cleaned_data["email"]

        self.context['user'] = user
        self.context['new_email'] = self.cleaned_data["email"]
        self.context['uid'] = urlsafe_base64_encode(force_bytes(user.pk))
        self.context['token'] = signing.dumps((user.pk, self.context['new_email']))

        kauth_send_mail(**self.sender, context=self.context)

        return user
