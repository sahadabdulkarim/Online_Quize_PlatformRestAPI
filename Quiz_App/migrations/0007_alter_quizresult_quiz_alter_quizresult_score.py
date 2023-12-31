# Generated by Django 4.2.3 on 2023-07-20 15:32

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("Quiz_App", "0006_alter_quiz_created_by"),
    ]

    operations = [
        migrations.AlterField(
            model_name="quizresult",
            name="quiz",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="quiz_results",
                to="Quiz_App.quiz",
            ),
        ),
        migrations.AlterField(
            model_name="quizresult",
            name="score",
            field=models.DecimalField(decimal_places=2, max_digits=5),
        ),
    ]
