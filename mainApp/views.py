from django.contrib.auth.models import User
from django.http.response import HttpResponse
from django.shortcuts import render,redirect
from django.http import HttpRequest,HttpResponseBadRequest
from django.contrib.auth import authenticate,login
from . import models
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
from .authentication import CustomAuthentication
# Create your views here.

def getTokenForUser(user):
    token=RefreshToken.for_user(user)
    return {
        'refresh': str(token),
        'access': str(token.access_token),
    }

def login(request :HttpRequest):
    if(request.method=="POST"):
        password=request.POST.get('password',False)
        email=request.POST.get('email',False)
        if(all((password,email))):
            users=models.User.objects.filter(email=email)
            flag=False
            for user in users:
                user=authenticate(username=user.username,password=password)
                if(user):
                    flag=True
                    break
            if(flag):
                return getLoggedInResponse(user)
            else:
                return render(request,'mainApp/login.html')
                
    else:
        return render(request,'mainApp/login.html')


def home(request: HttpRequest):
    try:
        user=getAuthUser(request)
    except:
        return redirect('login')

    params={
        'username':user.first_name,
        'address':user.usermodel.address,
        'email':user.email
    }
    return render(request,'mainApp/home.html',params)
    

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
                user=models.User.objects.create_user(username=username,password=password,email=email,first_name=username)
                usermodel=models.UserModel.objects.create(user=user,address=add)
                return getLoggedInResponse(user)
        else:
            params["error"]='passwords don`t match'        
    else:
        return render(request,'mainApp/signin.html')


def getLoggedInResponse(user):
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

@csrf_exempt
def changeProperty(request):
    edit = request.POST.get('edit',False)
    try:
        id = int(request.POST.get('id',0))
        user=getAuthUser(request)
        usermodel=user.usermodel

        if(id==1):
            user.first_name = request.POST.get('username','') if edit else ''
        elif(id==2):
            user.email = request.POST.get('email','') if edit else ''
        elif(id==3):
            usermodel.address=  request.POST.get('address','') if edit else ''

        user.save()
        usermodel.save()

    except Exception as e:
        print(e)
    finally:
        return redirect('home')


def getAuthUser(request):
    user,_=CustomAuthentication().authenticate(request)
    return user

def logout(request):
    resp = redirect('login')
    resp.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
    return resp