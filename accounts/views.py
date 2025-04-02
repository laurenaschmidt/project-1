from django.shortcuts import render
from django.contrib.auth import login as auth_login, authenticate, logout as auth_logout
from .forms import CustomUserCreationForm, CustomErrorList
from django.contrib.auth.forms import UserCreationForm, User
from django.shortcuts import redirect

from django.contrib.auth.decorators import login_required

from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import make_password
from django.contrib import messages
from .forms import PasswordResetForm 
from .forms import SelfServicePasswordResetForm

from django.contrib.auth.views import PasswordResetView

from django.contrib.auth.models import User
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from .forms import PasswordResetForm

class CustomPasswordResetView(PasswordResetView):
    template_name = 'registration/password_reset_form.html'

User = get_user_model()

def reset_password_view(request):
    if request.method == "POST":
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            new_password = form.cleaned_data["new_password"]
            
            try:
                user = User.objects.get(username=username)
                user.password = make_password(new_password)
                user.save()
                messages.success(request, "Password reset successfully!")
                return redirect("login")
            except User.DoesNotExist:
                messages.error(request, "User not found.")
    
    else:
        form = PasswordResetForm()

    return render(request, "reset_password.html", {"form": form})

def self_service_password_reset(request):
    if request.method == 'POST':
        print("sspr post")
        form = PasswordResetForm(request.POST)
        
        print("form.is_valid(): " + str(form.is_valid()))
        if form.is_valid():
            username = form.cleaned_data['username']
            new_password = form.cleaned_data['new_password']
            print("views sspr username: " + str(username))
            print("views sspr password: " + str(new_password))
            confirm_password = form.cleaned_data['confirm_password']
            
            # Retrieve the user by username
            try:
                user = User.objects.get(username=username)
                user.set_password(new_password)  # Set the new password
                user.save()  # Save the user with the new password
                
                # Optionally, update the session authentication to keep the user logged in
                update_session_auth_hash(request, user)
                
                #redirect to login
                return redirect('accounts.login')
            except User.DoesNotExist:
                form.add_error('username', 'User not found')  # Add error if user is not found
        else:
            print(form.errors)
        print("end if form isvalid")
    else:
        print("sspr else")
        form = PasswordResetForm()

    return render(request, 'accounts/self_service_password_reset.html', {'form': form})

@login_required
def logout(request):
    auth_logout(request)
    return redirect('home.index')

def login(request):
    template_data = {}
    template_data['title'] = 'Login'
    max_attempts = 3 
    if request.method == 'GET':
        return render(request, 'accounts/login.html',
            {'template_data': template_data})
    elif request.method == 'POST':
        username = request.POST.get('username')  # Using .get() avoids error
        password = request.POST.get('password')

        print("views login username: " + str(username))
        print("views login password: " + str(password))
        
        if not username or not password:
            template_data['error'] = 'Both fields are required.'
            return render(request, 'accounts/login.html', {'template_data': template_data})
        
        user = authenticate(request, username=username, password=password)

        if 'failed_attempts' not in request.session:
            request.session['failed_attempts'] = 0
        
        if user is None:
            request.session['failed_attempts'] += 1
            if request.session['failed_attempts'] >= max_attempts:
                request.session['failed_attempts'] = 0
                return redirect('accounts/self-service-password-reset')

            template_data['error'] = 'The username or password is incorrect. You have ' + str(max_attempts - request.session['failed_attempts']) + ' more attempt(s) until you will be prompted to reset password.'
            return render(request, 'accounts/login.html',
                {'template_data': template_data})
            
        else:
            auth_login(request, user)
            return redirect('home.index')
def signup(request):
    template_data = {}
    template_data['title'] = 'Sign Up'
    if request.method == 'GET':
        template_data['form'] = CustomUserCreationForm()
        return render(request, 'accounts/signup.html',
            {'template_data': template_data})
    elif request.method == 'POST':
        form = CustomUserCreationForm(request.POST, error_class=CustomErrorList)
        if form.is_valid():
            form.save()
            return redirect('accounts.login')
        else:
            template_data['form'] = form
            return render(request, 'accounts/signup.html',
                          {'template_data': template_data})
@login_required
def orders(request):
    template_data = {}
    template_data['title'] = 'Orders'
    template_data['orders'] = request.user.order_set.all()
    return render(request, 'accounts/orders.html',
        {'template_data': template_data})