from django.urls import path, include
from mp import views

urlpatterns = [
    path("",views.home, name="home"),
    path("register",views.register, name="register"),
    path("login",views.login, name="login"),
    path("index/<str:private_key>/",views.Operations, name="index"),
    path("owner/<str:private_key>/",views.owner, name="owner"),
    path("user/<str:private_key>/",views.user, name="user"),
    # path("display",views.display, name="display"),

    path("upload/<str:private_key>", views.uploader, name="upload"),
    path("grant/<str:private_key>", views.granter, name="grant"),
    path("revoke/<str:private_key>", views.revoker, name="revoke"),

    path("request/<str:private_key>", views.requester, name="request"),
    path("download/<str:private_key>", views.downloader, name="download"),
]



