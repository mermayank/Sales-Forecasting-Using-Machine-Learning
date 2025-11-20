from django.contrib import admin
from mp import models

admin.site.register(models.RegUser)
admin.site.register(models.File)
admin.site.register(models.Subscription)
