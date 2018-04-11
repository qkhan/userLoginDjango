from django.contrib.auth import login, get_user_model, logout
from django.shortcuts import render
from django.http import HttpResponseRedirect
from .forms import UserCreationForm, UserLoginForm


User = get_user_model()
# Create your views here.
def home(request):
    if request.user.is_authenticated:
        print(request.user.profile.city)
        return render(request, "accounts/home.html", {})


def register(request, *args, **kwargs):
    form = UserCreationForm(request.POST or None)
    if form.is_valid():
        form.save()
        print("user created")
        return HttpResponseRedirect("/login")
    return render(request, "accounts/register.html", {"form": form})


def user_login(request, *args, **kwargs):
	form = UserLoginForm(request.POST or None)
	if form.is_valid():
		# print("user created")
		user_obj = form.cleaned_data.get('user_obj')
		login(request, user_obj)
		return HttpResponseRedirect("/")
	return render(request, "accounts/login.html", {"form": form})


def user_logout(request):
	logout(request)
	return HttpResponseRedirect("/login")