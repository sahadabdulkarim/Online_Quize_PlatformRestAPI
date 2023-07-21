from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractUser

from django.utils import timezone

# Create your models here.


class User(AbstractUser):
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128, default="")

    def __str__(self):
        return self.username


class Quiz(models.Model):
    DIFFICULTY_CHOICES = (
        ("Easy", "Easy"),
        ("Medium", "Medium"),
        ("Hard", "Hard"),
    )

    title = models.CharField(max_length=255)
    topic = models.CharField(max_length=255)
    difficulty = models.CharField(max_length=10, choices=DIFFICULTY_CHOICES)
    date_created = models.DateField(default=timezone.now)
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="created_quizzes"
    )

    def __str__(self):
        return self.title


class Question(models.Model):
    quiz = models.ForeignKey(Quiz, related_name="questions", on_delete=models.CASCADE)
    text = models.TextField()

    def __str__(self):
        return self.text


class Choice(models.Model):
    question = models.ForeignKey(
        Question, on_delete=models.CASCADE, related_name="choices"
    )
    text = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)

    def __str__(self):
        return self.text


class QuizResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    quiz = models.ForeignKey(
        Quiz, related_name="quiz_results", on_delete=models.CASCADE
    )
    score = models.DecimalField(max_digits=5, decimal_places=2)

    def __str__(self):
        return f"{self.user.username}'s Result: {self.score}"
