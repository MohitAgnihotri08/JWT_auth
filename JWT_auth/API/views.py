from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.hashers import make_password
import requests
import jwt
from django.conf import settings
from jwt import ExpiredSignatureError, InvalidTokenError

def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
            return redirect('register')

        User.objects.create(username=username, password=make_password(password))
        messages.success(request, "Registration successful! Please log in.")
        return redirect('login')

    return render(request, "register.html")


def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        response = requests.post(
            "http://127.0.0.1:8000/api/token/",
            data={"username": username, "password": password}
        )
        print(response)

        if response.status_code == 200:
            tokens = response.json()
            request.session['access'] = tokens['access']
            request.session['refresh'] = tokens['refresh']
            return redirect('dashboard')
        else:
            messages.error(request, "Invalid credentials")
            return redirect('login')

    return render(request, "login.html")


def dashboard_view(request):
    access_token = request.session.get('access')

    if not access_token:
        return redirect('login')

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"])
        return render(request, "dashboard.html", {"user_id": payload.get("user_id")})
    except ExpiredSignatureError:
        messages.error(request, "Session expired. Please log in again.")
        return redirect('login')
    except InvalidTokenError:
        messages.error(request, "Invalid token. Please log in again.")
        return redirect('login')


def logout_view(request):
    request.session.flush()
    messages.success(request, "Logged out successfully.")
    return redirect('login')