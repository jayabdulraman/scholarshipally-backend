# Generated by Django 5.0.7 on 2024-08-14 01:10

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0016_ratelimit_createdat'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ratelimit',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
