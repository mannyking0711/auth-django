# Generated by Django 4.2.1 on 2023-06-02 12:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0004_alter_scanrequest_result'),
    ]

    operations = [
        migrations.AddField(
            model_name='openport',
            name='count',
            field=models.IntegerField(default=0),
        ),
    ]
