# Generated by Django 5.0.7 on 2024-07-26 21:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0010_rename_created_at_chats_createdat_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='chats',
            name='role',
            field=models.CharField(choices=[('user', 'user'), ('assistant', 'assistant'), ('system', 'system'), ('tool', 'tool')], max_length=50, verbose_name='Role'),
        ),
    ]