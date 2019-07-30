from django import forms

from django.core import signing

from django.core.exceptions import ValidationError

from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from django.contrib.auth.hashers import check_password
from django.contrib.auth.forms import UserCreationForm

from .models import KauthUser
from .utilities import kauth_send_mail


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
