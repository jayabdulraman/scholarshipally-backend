# Generated by Django 5.0.7 on 2024-07-22 21:09

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_alter_user_phone_number'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='chats',
            name='user_id',
        ),
    ]
