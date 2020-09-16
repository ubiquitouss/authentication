from django.urls import path ,include
from django.contrib import admin
from django.contrib.auth import views as auth_views
from . import views


urlpatterns = [
    path('',views.home, name='home'),
    path('login/',views.login_user, name='login'),
    path('logout/',views.logout_user, name='logout'),
    path('register/',views.register_user, name='register'),
    path('edit_profile/',views.edit_profile, name='edit_profile'),

    path('change_password/',views.change_password, name='change_password'),
    path('activate/<uidb64>/<token>/',views.activate, name='activate'),
    
    
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name="password/password_reset_confirm.html"), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password/password_reset_complete.html'), name='password_reset_complete'),  

    path("password_reset/", views.password_reset_request, name="password_reset"),    




#     path('',include('django.contrib.auth.urls')) 

]