# Generated by Django 4.2.1 on 2023-06-02 11:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0002_alter_scanrequest_track_vulnerability_openport'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanrequest',
            name='result',
            field=models.TextField(blank=True),
        ),
    ]
