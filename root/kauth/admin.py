from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import KauthUser


class KauthUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'is_staff', 'is_active')

    readonly_fields = ('last_login', 'date_joined')

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2'),
        }),
    )

    def get_action_choices(self, request):
        choices = super().get_action_choices(request)
        choices.pop(0)
        return choices


admin.site.register(KauthUser, KauthUserAdmin)
