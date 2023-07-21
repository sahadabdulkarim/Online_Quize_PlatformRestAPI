import django_filters

from .models import Quiz


class QuizFilter(django_filters.FilterSet):
    class Meta:
        model = Quiz
        fields = {
            "topic": ["exact"],
            "difficulty": ["exact"],
            "date_created": ["exact", "lt", "lte", "gt", "gte"],
        }
