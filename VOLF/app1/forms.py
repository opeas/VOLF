from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django import forms
from .models import VulnerabilityFound

class PasswordChangingForm(PasswordChangeForm):
    old_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'type':'password'}),
        label='Old password'
    )
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'type':'password'}),
        label='New password'
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'type':'password'}),
        label='Confirm new password'
    )

    class Meta:
        model = User
        fields = ('old_password', 'new_password1', 'new_password2')

class VulnerabilityForm(forms.ModelForm):
    class Meta:
        model = VulnerabilityFound
        fields = ['verified']
