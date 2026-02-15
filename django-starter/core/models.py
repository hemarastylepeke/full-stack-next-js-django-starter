from django.db import models
from django.contrib.auth import get_user_model

# Get user model from the settings
user = get_user_model()

# To do Model
class ToDo(models.Model):
    user = models.ForeignKey(user, on_delete=models.CASCADE, related_name='todos')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    completed = models.BooleanField(default=False)

    def __str__(self):
        return self.title
