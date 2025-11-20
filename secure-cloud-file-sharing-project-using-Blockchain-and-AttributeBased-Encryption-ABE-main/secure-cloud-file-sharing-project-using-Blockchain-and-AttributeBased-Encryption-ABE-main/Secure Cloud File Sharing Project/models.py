from django.db import models

class RegUser(models.Model):
    name = models.CharField(max_length=255)
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=80)
    department = models.CharField(max_length=255)
    subscription_period = models.CharField(max_length=100)
    private_key = models.CharField(max_length=66, blank=True, null=True)

    def __str__(self):
        return f"{self.name}"

    
class File(models.Model):
    file_id = models.CharField(max_length=66, unique=True)  # Like a bytes32 hash

    def __str__(self):
        return self.file_id

class Subscription(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='subscriptions')
    user_id = models.CharField(max_length=66)  # Like a bytes32
    user_keys = models.JSONField(default=list)  # Store keys as list of hex strings
    user_names = models.JSONField(default=list)  # Store names as list of strings

    class Meta:
        unique_together = ('file', 'user_id')

    def __str__(self):
        return f"Subscription: file={self.file.file_id}, user={self.user_id}"
    
