# Generated by Django 5.0.7 on 2024-07-26 17:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_alter_user_custom_instruction'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='chats',
            name='output',
        ),
        migrations.RemoveField(
            model_name='threads',
            name='metadata',
        ),
        migrations.AddField(
            model_name='chats',
            name='content',
            field=models.TextField(default='No data', max_length=500, verbose_name='Content'),
        ),
        migrations.AddField(
            model_name='chats',
            name='metadata',
            field=models.JSONField(blank=True, max_length=200, null=True, verbose_name='Metadata'),
        ),
        migrations.AddField(
            model_name='threads',
            name='path',
            field=models.CharField(blank=True, max_length=200, null=True, verbose_name='Path'),
        ),
    ]