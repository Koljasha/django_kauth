from django.urls import path

from. import views

app_name = 'kauth'

urlpatterns = [
    path('accounts/login/', views.KauthLoginView.as_view(), name='login'),
    path('accounts/logout/', views.KauthLogoutView.as_view(), name='logout'),

    path('accounts/profile/email_change/', views.KauthEmailChangeView.as_view(), name='email_change'),
    path('accounts/profile/email_change/<uidb64>/<token>/', views.KauthEmailChangeConfirmView.as_view(), name='email_change_confirm'),
    path('accounts/profile/password_change/', views.KauthPasswordChangeView.as_view(), name='password_change'),
    path('accounts/profile/profile_change/', views.KauthUserChangeView.as_view(), name='profile_change'),
    path('accounts/profile/delete/', views.KauthDeleteUserView.as_view(), name='profile_delete'),
    path('accounts/profile/', views.KauthProfile.as_view(), name='profile'),

    path('accounts/password_reset/', views.KauthPasswordResetView.as_view(), name='password_reset'),
    path('accounts/password_reset/<uidb64>/<token>/', views.KauthPasswordResetConfirmView.as_view(), name='password_reset_confirm'),

    path('accounts/registration/', views.KauthRegistrationView.as_view(), name='registration'),
    path('accounts/registration/<uidb64>/<token>/', views.KauthRegistrationConfirmView.as_view(), name='registration_confirm'),

    path('accounts/', views.KauthRedirectToProfileView.as_view(), name='redirect_to_profile'),

    path('pp/', views.PrivatePage.as_view(), name='pp'),
    path('', views.KauthIndex.as_view(), name='index'),
]
