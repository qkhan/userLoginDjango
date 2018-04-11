# Generated by Django 2.0.4 on 2018-04-09 09:11

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_profile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='myuser',
            name='username',
            field=models.CharField(max_length=255, unique=True, validators=[django.core.validators.RegexValidator(code='invalide_username', message='Username must be Alphanumeric or contain any of the following: ". @ + - "', regex='^[a-zA-Z0-9.+-]*$')]),
        ),
    ]