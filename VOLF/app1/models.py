from django.db import models

# Create your models here.
class VulnerabilityFound(models.Model):
    date = models.DateField()
    product = models.CharField(max_length=50)
    link = models.CharField(max_length=150)
    CVE = models.CharField(max_length=150, default='No info about CVE')
    CVSS = models.BooleanField(default=False)
    verified = models.BooleanField(default=False)
