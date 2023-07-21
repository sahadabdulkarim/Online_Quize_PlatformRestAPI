# urls.py

from django.urls import path
from .views import (
    QuizAnalytics,
    QuizListView,
    UserListView,
    UserProfileView,
    UserRegistrationView,
    UserLoginView,
    UserLogoutView,
    QuizCreateView,
    QuizTakeView,
    QuizSubmitView,
    QuizResultListView,
    UserListView,
    UserDetailView,
)

urlpatterns = [
    path("api/register/", UserRegistrationView.as_view(), name="user-registration"),
    path("api/login/", UserLoginView.as_view(), name="user-login"),
    path("api/logout/", UserLogoutView.as_view(), name="user-logout"),
    path("api/quizzes/create/", QuizCreateView.as_view(), name="quiz-create"),
    path("api/users/", UserListView.as_view(), name="user-list"),
    path("api/quizzes/", QuizListView.as_view(), name="quiz-list"),
    path(
        "api/quizzes/<str:username>/", QuizListView.as_view(), name="quiz-list-by-user"
    ),
    path("api/quizzes/<int:pk>/take/", QuizTakeView.as_view(), name="quiz-take"),
    path("api/quizzes/<int:pk>/submit/", QuizSubmitView.as_view(), name="quiz-submit"),
    path("api/results/", QuizResultListView.as_view(), name="quiz-results"),
    path("api/user/profile/", UserProfileView.as_view(), name="user-profile"),
    path("api/users/", UserListView.as_view(), name="user-list"),
    path("api/users/<int:pk>/", UserDetailView.as_view(), name="user-detail"),
    path(
        "api/quizzes/<int:quiz_id>/analytics/",
        QuizAnalytics.as_view(),
        name="quiz_analytics",
    ),
]
