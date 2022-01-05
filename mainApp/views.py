from django.shortcuts import render,redirect
from django.http import HttpRequest,HttpResponseBadRequest
from django.contrib.auth import authenticate
from . import models
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.decorators import *
# Create your views here.

def getTokenForUser(user):
    token=RefreshToken.for_user(user)
    return {
        'refresh': str(token),
        'access': str(token.access_token),
    }

def login(request :HttpRequest):
    return render(request,'mainApp/login.html')


def home(request: HttpRequest):
    return redirect('login')

def signup(request :HttpRequest):
    params={}
    if(request.method=='POST'):
        username=request.POST.get('username',False)
        password=request.POST.get('password',False)
        conf=request.POST.get('confirm',False)
        add=request.POST.get('address',False)
        email=request.POST.get('email',False)
        
        if(conf==password):

            if(all((username,password,conf,add,email))):
                user=models.User.objects.create_user(username=username,password=password,email=email)
                usermodel=models.UserModel.objects.create(user=user,address=add)
                response = redirect('home')  
                data= getTokenForUser(user)
                response.set_cookie(
                    key = settings.SIMPLE_JWT['AUTH_COOKIE'], 
                    value = data["access"],
                    expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                    secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                    httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                    samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                )
                return response
        else:
            params["error"]='passwords don`t match'        
    else:
        return render(request,'mainApp/signin.html')


