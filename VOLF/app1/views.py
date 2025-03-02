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
        
        def zbierz_numery_cve(cve_string):
            cve_pattern = r'CVE-\d+-\d+'
            cve_list = re.findall(cve_pattern, cve_string)
            cve_set = set()
            unique_cve_list = []
            for cve in cve_list:
                if cve not in cve_set:
                    unique_cve_list.append(cve)
                    cve_set.add(cve)
            return unique_cve_list
        
        cve_list = zbierz_numery_cve(cve_field)
        
        # Call the collect_cve_data function with the correct parameters
        cve, source, affected_versions, recommended_version, cvss, priority, description, rejected = collect_cve_data(cve_list, cvss_checkbox)
        
        return render(request, "get_cve_details.html", {
            "cve_field": cve_field,  # Original CVE input
            "resultCVE": cve,  # Filtered CVE numbers
            "result1": source,  # Source
            "result2": affected_versions,  # Affected versions
            "result3": recommended_version,  # Recommended version
            "result4": cvss,  # CVSS score
            "result5": priority,  # Priority
            "result6": description,  # Description
            "result7": rejected,  # Rejected CVEs
        })
