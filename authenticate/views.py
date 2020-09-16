from django.shortcuts import render,redirect
from django.contrib.auth import authenticate, login, logout,update_session_auth_hash
from django.contrib.auth.forms import UserCreationForm, UserChangeForm, PasswordChangeForm, PasswordResetForm
from django.contrib import messages
from .forms import SignUpForm,EditProfileForm


from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage, send_mail, BadHeaderError
from django.http import HttpResponse
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.db.models.query_utils import Q
UserModel = get_user_model()
from .forms import SignUpForm
# from .tokens import account_activation_token


def home(request):
    return render(request, 'authenticate/home.html',{})


def login_user(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            messages.success(request,('You have been logged in'))
            return redirect('home')

        else:
            messages.success(request,('Error logging in! Please try again'))
            return redirect('login')
    else:
        return render(request, 'authenticate/login.html',{})

def logout_user(request):
    logout(request)
    messages.success(request,('You have been logged out'))
    return redirect('home')

def register_user(request):
    if request.method == 'POST':
        form= SignUpForm(request.POST)
        if form.is_valid():
            user= form.save(commit=False)
            username=form.cleaned_data['username']
            password=form.cleaned_data['password1']
            # user = authenticate(request, username=username, password=password)
            # login(request, user)
            messages.success(request,('You have registered'))
            user.is_active=False
            user.save()
            current_site = get_current_site(request)
            mail_subject = 'Activate your account.'
            message = render_to_string('authenticate/acc_active_email.html', {
                                        'user': user,
                                        'domain': current_site.domain,
                                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                                        'token': default_token_generator.make_token(user),
                                        }
                                        )
            to_email = form.cleaned_data.get('email')
            email = EmailMessage(
                    mail_subject, message, to=[to_email]
                    )
            email.send()
            return HttpResponse('Please confirm your email address to complete the registration')

            # return redirect('home')
    else:
        form = SignUpForm()
    context={'form':form} 
    return render(request, 'authenticate/register.html', context)

def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = UserModel._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user,token):
        user.is_active = True
        user.save()
        return HttpResponse('Thank you for your email confirmation.Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')



def edit_profile(request):
    if request.method == 'POST':
        form= EditProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request,'Profile saved successfully')
            return redirect('home')
    else:
        form = EditProfileForm(instance=request.user)
    context={'form':form} 
    return render(request, 'authenticate/edit_profile.html', context)


def change_password(request):
    if request.method == 'POST':
        form= PasswordChangeForm(data=request.POST, user=request.user)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request,form.user)
            messages.success(request,'Password changed successfully')
            return redirect('home')
    else:
        form = PasswordChangeForm(user=request.user)
    context={'form':form} 
    return render(request, 'authenticate/change_password.html', context)

def password_reset_request(request):
	if request.method == "POST":
		password_reset_form = PasswordResetForm(request.POST)
		if password_reset_form.is_valid():
			data = password_reset_form.cleaned_data['email']
			associated_users = User.objects.filter(Q(email=data))
			if associated_users.exists():
				for user in associated_users:
					subject = "Password Reset Requested"
					email_template_name = "password/password_reset_email.html"
					c = {
					"email":user.email,
					'domain':'127.0.0.1:8000',
					'site_name': 'Website',
					"uid": urlsafe_base64_encode(force_bytes(user.pk)),
					"user": user,
					'token': default_token_generator.make_token(user),
					'protocol': 'http',
					}
					email = render_to_string(email_template_name, c)
					try:
						send_mail(subject, email, 'tawkir.ph@gmail.com' , [user.email], fail_silently=False)
					except BadHeaderError:
						return HttpResponse('Invalid header found.')
					return redirect ("/password_reset/done/")
	password_reset_form = PasswordResetForm()
	return render(request=request, template_name="password/password_reset.html", context={"password_reset_form":password_reset_form})