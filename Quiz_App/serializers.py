# serializers.py

from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Quiz, Question, Choice, QuizResult
from .models import User
from django.db.models import Avg, Max, Min, Count


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ("id", "username", "email", "password")
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = self.Meta.model(**validated_data)
        user.set_password(password)
        user.save()
        return user

    def update(self, instance, validated_data):
        if "password" in validated_data:
            password = validated_data.pop("password")
            instance.set_password(password)
        return super().update(instance, validated_data)


class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ("id", "username", "email")


class ChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ("id", "text")


class QuestionSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True)

    class Meta:
        model = Question
        fields = ("id", "text", "choices")


class QuizSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True)
    created_by = serializers.ReadOnlyField(source="created_by.username")

    class Meta:
        model = Quiz
        fields = [
            "id",
            "title",
            "topic",
            "difficulty",
            "created_by",
            "date_created",
            "questions",
        ]

    def create(self, validated_data):
        questions_data = validated_data.pop("questions")
        quiz = Quiz.objects.create(**validated_data)
        for question_data in questions_data:
            choices_data = question_data.pop("choices")
            question = Question.objects.create(quiz=quiz, **question_data)
            for choice_data in choices_data:
                Choice.objects.create(question=question, **choice_data)
        return quiz


class QuizListSerializer(serializers.ModelSerializer):
    created_by = serializers.ReadOnlyField(source="created_by.username")
    questions = QuestionSerializer(many=True, read_only=True)

    class Meta:
        model = Quiz
        fields = [
            "id",
            "created_by",
            "title",
            "date_created",
            "topic",
            "difficulty",
            "questions",
        ]


class QuizTakeSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True, read_only=True)

    class Meta:
        model = Quiz
        fields = ("id", "title", "questions")

    def validate(self, data):
        user = self.context["request"].user
        quiz_id = data["id"]
        if QuizResult.objects.filter(user=user, quiz_id=quiz_id).exists():
            raise serializers.ValidationError("You have already attended this quiz.")
        return data


class QuizSubmitSerializer(serializers.Serializer):
    quiz_id = serializers.IntegerField()
    answers = serializers.ListField(child=serializers.IntegerField(), allow_empty=False)


class QuizResultSerializer(serializers.ModelSerializer):
    quiz_title = serializers.ReadOnlyField(source="quiz.title")

    class Meta:
        model = QuizResult
        fields = ("quiz_title", "score")


class QuizSummarySerializer(serializers.ModelSerializer):
    class Meta:
        model = Quiz
        fields = ("id", "title")


class UserProfileSerializer(serializers.ModelSerializer):
    quizzes_created = QuizSummarySerializer(many=True, read_only=True)

    class Meta:
        model = get_user_model()
        fields = ("id", "username", "email", "quizzes_created")


# ----------------------------------
from rest_framework import serializers


class QuizAnalyticsSerializer(serializers.Serializer):
    title = serializers.CharField()
    quiz_id = serializers.IntegerField()
    difficulty = serializers.CharField()
    total_quizzes = serializers.IntegerField()
    created_by = serializers.CharField()
    quiz_overview = serializers.DictField(child=serializers.CharField())
    performance_metrics = serializers.DictField(child=serializers.FloatField())
    most_answered_questions = serializers.ListField(child=serializers.CharField())
    least_answered_questions = serializers.ListField(child=serializers.CharField())
