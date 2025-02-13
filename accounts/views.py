from django.shortcuts import render
from django.contrib.auth import login as auth_login, authenticate, logout as auth_logout
from .forms import CustomUserCreationForm, CustomErrorList
from django.contrib.auth.forms import UserCreationForm, User
from django.shortcuts import redirect

from django.contrib.auth.decorators import login_required


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
        user = authenticate(
            request,
            username = request.POST['username'],
            password = request.POST['password']
        )

        if 'failed_attempts' not in request.session:
            request.session['failed_attempts'] = 0
        
        if user is None:
            request.session['failed_attempts'] += 1
            if request.session['failed_attempts'] >= max_attempts:
                request.session['failed_attempts'] = 0
                return redirect('/accounts/password_reset/')

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