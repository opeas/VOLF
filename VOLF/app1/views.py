from django.shortcuts import render, redirect
from django.contrib.auth.views import PasswordChangeView
from django.urls import reverse_lazy
from .forms import PasswordChangingForm
from app1.models import VulnerabilityFound

import re

from app1.scripts.get_cve_details import collect_cve_data

class PasswordsChangeView(PasswordChangeView):
    form_class = PasswordChangingForm
    success_url = reverse_lazy('home')

def home(request):
    # If the form was submitted, update the record
    if request.method == 'POST':
        vulnerability_id = request.POST.get('vulnerability_id')
        if vulnerability_id:
            # Retrieve the record based on ID
            vulnerability = VulnerabilityFound.objects.get(id=vulnerability_id)
            # Toggle the 'verified' status
            vulnerability.verified = not vulnerability.verified
            vulnerability.save()
            # After saving, redirect to the home page
            return redirect('home')

    # Retrieve the latest 20 records
    newest_vulnerabilities = VulnerabilityFound.objects.order_by('-id')[:20]
    
    return render(request, 'home.html', {'vulnerabilities': newest_vulnerabilities})

def get_cve_details(request):
    return render(request, 'get_cve_details.html')

def get_cve_details_(request):
    if request.method == "POST":
        cve_field = request.POST.get("cve_field", "")
        if not cve_field:
            return render(request, 'get_cve_details.html')
        
        cvss_checkbox = request.POST.get("cvss_checkbox") == "true"
        
        def get_cve_numbers(cve_string):
            cve_pattern = r'CVE-\d+-\d+'
            cve_list = re.findall(cve_pattern, cve_string)
            cve_set = set()
            unique_cve_list = []
            for cve in cve_list:
                if cve not in cve_set:
                    unique_cve_list.append(cve)
                    cve_set.add(cve)
            return unique_cve_list
        
        cve_list = get_cve_numbers(cve_field)
        
        if cve_list:  # Only call collect_cve_data if cve_list is not empty
            cve, source, affected_versions, recommended_version, cvss, priority, description, rejected = collect_cve_data(cve_list, cvss_checkbox)
            return render(request, "get_cve_details.html", {
                "cve_field": cve_field,
                "resultCVE": cve,
                "result1": source,
                "result2": affected_versions,
                "result3": recommended_version,
                "result4": cvss,
                "result5": priority,
                "result6": description,
                "result7": rejected,
            })
        else:
            # Handle case when no CVEs are found in the input
            return render(request, "get_cve_details.html", {
                "cve_field": cve_field,
                "result1": "No valid CVE IDs found in input",
                "result2": "No valid CVE IDs found in input",
                "result3": "No valid CVE IDs found in input",
                "result4": "No valid CVE IDs found in input",
                "result5": "No valid CVE IDs found in input",
                "result6": "No valid CVE IDs found in input",
            })