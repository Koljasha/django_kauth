from django.urls import reverse_lazy
from django.shortcuts import redirect, get_object_or_404

from django.core import signing
from django.core.signing import BadSignature
from django.core.exceptions import ValidationError

from django.utils.http import urlsafe_base64_decode
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters

from django.views.generic.base import TemplateView, RedirectView
from django.views.generic.edit import CreateView, UpdateView, DeleteView

from django.contrib.auth import logout
from django.contrib.auth.views import UserModel
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.views import PasswordChangeView
from django.contrib.auth.views import PasswordResetView, PasswordResetConfirmView
from django.contrib.auth.mixins import LoginRequiredMixin

from django.contrib.sites.shortcuts import get_current_site

from django.contrib import messages
from django.contrib.messages.views import SuccessMessageMixin

from .models import KauthUser
from .forms import KauthAuthenticationForm, KauthRegistrationForm, KauthUserChangeForm, KauthEmailChangeForm
from .utilities import kauth_send_mail


class KauthIndex(TemplateView):
    template_name = 'kauth/index.html'


class PrivatePage(LoginRequiredMixin, TemplateView):
    template_name = 'kauth/ppage.html'


class KauthUserIsAnonymousMixin:
    def dispatch(self, request, *args, **kwargs):
        if self.request.user.is_authenticated:
            messages.add_message(request, messages.INFO, 'Вы уже авторизованы')
            return redirect(reverse_lazy('kauth:profile'))
        return super().dispatch(request, *args, **kwargs)


class KauthLoginView(KauthUserIsAnonymousMixin, LoginView):
    form_class = KauthAuthenticationForm
    template_name = 'kauth/login_form.html'


class KauthRedirectToProfileView(RedirectView):
    url = reverse_lazy('kauth:profile')
    permanent = True


class KauthLogoutView(LogoutView):
    next_page = reverse_lazy('kauth:index')

    def dispatch(self, request, *args, **kwargs):
        messages.add_message(request, messages.SUCCESS, 'Возвращайтесь...')
        return super().dispatch(request, *args, **kwargs)


class KauthProfile(LoginRequiredMixin, TemplateView):
    template_name = 'kauth/profile.html'


class KauthUserChangeView(SuccessMessageMixin, LoginRequiredMixin, UpdateView):
    model = KauthUser
    form_class = KauthUserChangeForm

    template_name = 'kauth/user_change_form.html'
    success_url = reverse_lazy('kauth:profile')
    success_message = 'Данные пользователя успешно изменены'

    def dispatch(self, request, *args, **kwargs):
        self.user_id = request.user.pk
        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        if not queryset:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, pk=self.user_id)


class KauthPasswordChangeView(SuccessMessageMixin, LoginRequiredMixin, PasswordChangeView):
    template_name = 'kauth/password_change_form.html'
    success_url = reverse_lazy('kauth:profile')
    success_message = 'Пароль успешно изменен'

    from_email = None
    subject_template_name = 'email/password_change_subject.txt'
    email_template_name = 'email/password_change_email.html'
    extra_email_context = None

    def form_valid(self, form):
        sender = {
            'from_email': self.from_email,
            'subject_template_name': self.subject_template_name,
            'email_template_name': self.email_template_name,
            'to_email': self.request.user.email
        }
        context = {
            'user': self.request.user.username,
            'email': self.request.user.email,
            'extra_email_context': self.extra_email_context
        }
        kauth_send_mail(**sender, context=context)
        return super().form_valid(form)


class KauthEmailChangeView(SuccessMessageMixin, LoginRequiredMixin, UpdateView):
    model = KauthUser
    form_class = KauthEmailChangeForm

    template_name = 'kauth/email_change_form.html'
    success_url = reverse_lazy('kauth:profile')
    success_message = 'Отправлено письмо для подтверждения изменения электронного адреса'

    from_email = None
    subject_template_name = 'email/email_change_subject.txt'
    email_template_name = 'email/email_change_email.html'
    extra_email_context = None

    def dispatch(self, request, *args, **kwargs):
        self.user_id = request.user.pk
        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        if not queryset:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, pk=self.user_id)

    def form_valid(self, form):
        protocol = 'https' if self.request.is_secure() else 'http'
        current_site = get_current_site(self.request)

        form.context = {
            'protocol': protocol,
            'site_name': current_site.name,
            'domain': current_site.domain,
            'extra_email_context': self.extra_email_context,
            'old_email': self.request.user.email
        }
        form.sender = {
            'from_email': self.from_email,
            'subject_template_name': self.subject_template_name,
            'email_template_name': self.email_template_name,
        }
        return super().form_valid(form)


class KauthEmailChangeConfirmView(RedirectView):
    url = reverse_lazy('kauth:profile')

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        assert 'uidb64' in kwargs and 'token' in kwargs

        user = self.get_user(kwargs['uidb64'])
        token = self.get_token(kwargs['token'])

        if user is None or token is None or user.pk != token[0]:
            messages.add_message(request, messages.ERROR,
                                 'Некорректная ссылка')
        else:
            user.email = token[1]
            user.save()
            messages.add_message(request, messages.SUCCESS,
                                 'Адрес электронной почты изменен')

        return super().dispatch(request, *args, **kwargs)

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist, ValidationError):
            user = None
        return user

    def get_token(self, token):
        try:
            token = signing.loads(token)
        except BadSignature:
            token = None
        return token


class KauthPasswordResetView(SuccessMessageMixin, PasswordResetView):
    template_name = 'kauth/password_reset_form.html'
    success_url = reverse_lazy('kauth:index')
    success_message = 'На указанный адрес отправлено письмо для сброса пароля'

    subject_template_name = 'email/password_reset_subject.txt'
    email_template_name = 'email/password_reset_email.html'


class KauthPasswordResetConfirmView(SuccessMessageMixin, PasswordResetConfirmView):
    template_name = 'kauth/password_reset_confirm.html'
    success_url = reverse_lazy('kauth:login')
    success_message = 'Пароль успешно сброшен'


class KauthRegistrationView(SuccessMessageMixin, KauthUserIsAnonymousMixin, CreateView):
    form_class = KauthRegistrationForm

    template_name = 'kauth/registration_form.html'
    success_url = reverse_lazy('kauth:index')
    success_message = 'На указанный адрес отправлено письмо для подтверждения регистрации'

    from_email = None
    subject_template_name = 'email/registration_subject.txt'
    email_template_name = 'email/registration_email.html'
    extra_email_context = None

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def form_valid(self, form):
        protocol = 'https' if self.request.is_secure() else 'http'
        current_site = get_current_site(self.request)

        form.context = {
            'protocol': protocol,
            'site_name': current_site.name,
            'domain': current_site.domain,
            'extra_email_context': self.extra_email_context
        }
        form.sender = {
            'from_email': self.from_email,
            'subject_template_name': self.subject_template_name,
            'email_template_name': self.email_template_name,
        }
        return super().form_valid(form)


class KauthRegistrationConfirmView(RedirectView):
    url = reverse_lazy('kauth:login')

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        assert 'uidb64' in kwargs and 'token' in kwargs

        user = self.get_user(kwargs['uidb64'])
        token = self.get_token(kwargs['token'])

        if user is None or token is None or user.date_joined.timestamp() != token:
            messages.add_message(request, messages.ERROR,
                                 'Некорректная ссылка регистрации')
        else:
            if user.is_active:
                messages.add_message(
                    request, messages.WARNING, 'Пользователь уже зарегистрирован')
            else:
                user.is_active = True
                user.save()
                messages.add_message(
                    request, messages.SUCCESS, 'Регистрация успешно произведена')

        return super().dispatch(request, *args, **kwargs)

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist, ValidationError):
            user = None
        return user

    def get_token(self, token):
        try:
            token = signing.loads(token)
        except BadSignature:
            token = None
        return token


class KauthDeleteUserView(LoginRequiredMixin, DeleteView):
    model = KauthUser
    template_name = 'kauth/user_delete_form.html'
    success_url = reverse_lazy('kauth:index')

    def dispatch(self, request, *args, **kwargs):
        self.user_id = request.user.pk
        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        if not queryset:
            queryset = self.get_queryset()
        return get_object_or_404(queryset, pk=self.user_id)

    def post(self, request, *args, **kwargs):
        logout(request)
        messages.add_message(request, messages.SUCCESS, 'Пользователь успешно удален')
        return super().post(request, *args, **kwargs)
