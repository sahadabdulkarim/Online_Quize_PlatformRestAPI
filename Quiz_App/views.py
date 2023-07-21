from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from django.contrib.auth.models import User
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend

from Quiz_App import models
from .filters import QuizFilter
from Quiz_App.models import Choice, Quiz, QuizResult
from .serializers import (
    QuizListSerializer,
    QuizSubmitSerializer,
    QuizTakeSerializer,
    UserListSerializer,
    UserProfileSerializer,
    UserSerializer,
    QuizResultSerializer,
)
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import CreateAPIView
from .serializers import QuizSerializer, UserSerializer
from rest_framework import generics, permissions
import logging
from rest_framework import status
from django.contrib.auth import get_user_model

User = get_user_model()

logger = logging.getLogger(__name__)


class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            )
        else:
            return Response({"error": "Invalid credentials"}, status=400)


class UserLogoutView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh")

        try:
            user = request.user
            user.outstanding_token = None
            user.save()

            if refresh_token:
                refresh_token = RefreshToken(refresh_token)
                refresh_token.blacklist()

            return Response({"message": "User logout successful"})

        except Exception as e:
            return Response({"error": "Invalid token"}, status=400)


class UserListView(generics.ListCreateAPIView):
    queryset = get_user_model().objects.all()
    permission_classes = (permissions.IsAdminUser,)

    def get_serializer_class(self):
        if self.request.method == "POST":
            return UserSerializer
        return UserListSerializer


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
    permission_classes = (permissions.IsAdminUser,)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({"detail": "User deleted"}, status=status.HTTP_204_NO_CONTENT)


class QuizCreateView(CreateAPIView):
    serializer_class = QuizSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        return self.queryset.filter(created_by=self.request.user)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class QuizListView(generics.ListAPIView):
    queryset = Quiz.objects.all()
    serializer_class = QuizListSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = QuizFilter

    def get_queryset(self):
        queryset = super().get_queryset()
        username = self.kwargs.get("username")
        if username:
            queryset = queryset.filter(created_by__username=username)
        return queryset


class QuizTakeView(generics.RetrieveAPIView):
    queryset = Quiz.objects.all()
    serializer_class = QuizTakeSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        user = request.user
        quiz_id = instance.id

        if QuizResult.objects.filter(user=user, quiz_id=quiz_id).exists():
            return Response(
                {"detail": "You have already attended this quiz."}, status=403
            )

        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class QuizSubmitView(generics.GenericAPIView):
    serializer_class = QuizSubmitSerializer
    permission_classes = [IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, pk):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        quiz_id = serializer.validated_data["quiz_id"]
        answers = serializer.validated_data["answers"]

        try:
            quiz = Quiz.objects.get(pk=quiz_id)
        except Quiz.DoesNotExist:
            return Response(
                {"detail": "Quiz not found."}, status=status.HTTP_404_NOT_FOUND
            )
        try:
            result = QuizResult.objects.get(quiz=quiz, user=request.user)
            return Response(
                {"detail": "Quiz already taken."},
                status=status.HTTP_403_FORBIDDEN,
            )
        except QuizResult.DoesNotExist:
            pass
        if len(answers) != quiz.questions.count():
            return Response(
                {"detail": "Invalid number of answers provided."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        score = 0
        for question, answer_id in zip(quiz.questions.all(), answers):
            try:
                selected_choice = question.choices.get(pk=answer_id)
                if selected_choice.is_correct:
                    score += 1
            except Choice.DoesNotExist:
                return Response(
                    {"detail": "Invalid choice ID provided for question."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        # Save the result only if it is the first attempt
        try:
            # Calculate the passing percentage
            passing_percentage = 40
            total_questions = quiz.questions.count()
            passing_score = int(total_questions * (passing_percentage / 100))
            remark = "passed" if score >= passing_score else "failed"

            result = QuizResult.objects.get(quiz=quiz, user=request.user)
        except QuizResult.DoesNotExist:
            result = QuizResult.objects.create(
                quiz=quiz, user=request.user, score=score
            )

        return Response(
            {"score": score, "result_id": result.pk, "remark": remark},
            status=status.HTTP_200_OK,
        )


class QuizResultListView(generics.ListAPIView):
    queryset = QuizResult.objects.all()
    serializer_class = QuizResultSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def list(self, request, *args, **kwargs):
        user = request.user
        queryset = self.get_queryset().filter(user=user)

        total_score = sum(result.score for result in queryset)

        serializer = self.serializer_class(queryset, many=True)

        response_data = {
            "username": user.username,
            "total_score": total_score,
            "results": serializer.data,
        }

        return Response(response_data)


class UserProfileView(generics.RetrieveAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def get_object(self):
        user = self.request.user
        quizzes_created = Quiz.objects.filter(created_by=user)
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "quizzes_created": quizzes_created,
        }


# -------------------------------------------------------------
# views.py

from rest_framework import generics, permissions, status
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.db.models import Avg, Max, Min, Count
from .models import Quiz, QuizResult, Question, Choice
from .serializers import QuizAnalyticsSerializer


class QuizAnalytics(APIView):
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]
    serializer_class = QuizAnalyticsSerializer

    def get(self, request, quiz_id, *args, **kwargs):
        try:
            quiz = Quiz.objects.get(pk=quiz_id)
        except Quiz.DoesNotExist:
            return Response(
                {"detail": "Quiz not found."}, status=status.HTTP_404_NOT_FOUND
            )

        total_quiz_takers = (
            QuizResult.objects.filter(quiz=quiz).values("user").distinct().count()
        )
        passed_quiz_takers = (
            QuizResult.objects.filter(quiz=quiz, score__gte=40)
            .values("user")
            .distinct()
            .count()
        )

        pass_percentage = (
            (passed_quiz_takers / total_quiz_takers) * 100
            if total_quiz_takers > 0
            else 0
        )
        total_quizzes = Quiz.objects.count()
        quiz_title = quiz.title
        difficulty = quiz.difficulty
        created_by = quiz.created_by.username

        # Get all quiz results for the current quiz
        quiz_submissions = QuizResult.objects.filter(quiz=quiz)

        # Calculate average, highest, and lowest score for the current quiz
        average_score = quiz_submissions.aggregate(Avg("score"))["score__avg"]
        highest_score = quiz_submissions.aggregate(Max("score"))["score__max"]
        lowest_score = quiz_submissions.aggregate(Min("score"))["score__min"]

        questions = Question.objects.filter(quiz=quiz)
        quiz_overview = {
            "no_of_questions_in_this_quiz": quiz.questions.count(),
            "no_of_quiz_takers": total_quiz_takers,
            "pass_percentage": pass_percentage,
        }
        question_statistics = []
        for question in questions:
            total_answers = Choice.objects.filter(question=question).count()
            question_statistics.append(
                {
                    "question_text": question.text,
                    "total_answers": total_answers,
                }
            )

        most_answered_questions = sorted(
            question_statistics, key=lambda x: x["total_answers"], reverse=True
        )[:2]
        least_answered_questions = sorted(
            question_statistics, key=lambda x: x["total_answers"]
        )[:2]

        analytics_data = {
            "total_quizzes": total_quizzes,
            "quiz_id": quiz_id,
            "title": quiz_title,
            "difficulty": difficulty,
            "created_by": created_by,
            "quiz_overview": quiz_overview,
            "performance_metrics": {
                "quiz_id": quiz.id,
                "quiz_title": quiz.title,
                "average_score": average_score,
                "highest_score": highest_score,
                "lowest_score": lowest_score,
            },
            "most_answered_questions": [
                q["question_text"] for q in most_answered_questions
            ],
            "least_answered_questions": [
                q["question_text"] for q in least_answered_questions
            ],
        }

        serializer = QuizAnalyticsSerializer(data=analytics_data)
        serializer.is_valid()
        return Response(serializer.data)
