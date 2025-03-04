# VOLF - Vulnerability Observation &amp; Logging Framework
A Python application in Django framework for automating the discovery, logging, and assessment of vulnerabilities from online sources.

It provides a GUI where vulnerabilities discovered using the [CVE-Scanner](https://github.com/opeas/CVE-Scanner) script are logged and enables quick retrieval of key information about one or multiple vulnerabilities from the [CVE MITRE database](https://cve.mitre.org/).

App Demonstration  
-------------------
https://github.com/user-attachments/assets/994b546d-b176-4243-ac94-01440c6c5e18

Key Functionalities
-------------------
- Vulnerability Scanning: Using the ```CVE-Scanner.py``` script, the application retrieves the latest CVEs from software vendors websites.
- Vulnerability Logging: Discovered vulnerabilities are logged in a SQLite database. In the "Latest Vulnerabilities" tab, the 20 most recent vulnerabilities are displayed.
- CVE Analysis: In the "Get CVE Details" tab, you can quickly search the MITRE CVE database for information on specific CVEs that you have entered. This is especially useful when a vulnerability listed in "Latest Vulnerabilities" also includes new CVE numbers. Paste the CVE numbers into the text field, and the script will fetch the vulnerability details via an API, returning the information in a user-friendly format.

  In the search, you can check the "Exclude CVEs with CVSS below 7.0" checkbox. By selecting this option, vulnerabilities with a severity lower than "High" will be automatically excluded.

Implementation
-------------------
After downloading the folder and installing the required libraries (make sure you have ```django``` and ```requests```), navigate to the ```/VOLF``` folder and execute the following commands:
- ```python manage.py makemigrations app1``` - Creates migration files based on the models in ```app1```.
- ```python manage.py migrate``` - Applies the migrations to the database, synchronizing it with the models.
- ```python manage.py createsuperuser``` - Creates an administrator account.

Next, log into the ```/admin``` panel with the created account and create additional accounts for other users.

Annotations
-------------------
- The most convenient way to use the ```CVE-Scanner.py``` script is to run it via a cronjob, which allows the application to automatically update the database when vulnerabilities were discovered.
- The various functions in ```get_cve_details.py``` have been designed for different types of searches. The results are returned in different formats for a single CVE, for 2-4 CVEs, and for more than 4 CVEs, ensuring the output is always displayed in the most optimal format.
- I would recommend to set up ```change_checkbox.py``` for automatic execution - this will change the status of unverified vulnerabilities to "Verified" after a specified period.
- Users can change their account passwords in the application interface. However, new accounts can only be created in the Django admin panel.
- The website’s theme color is stored in the browser cookies.

> [!NOTE]
> The script should only be used in compliance with the terms of the websites it accesses. The MITRE CVE API also has specific usage limits and policies.
> Users must ensure that their actions align with the sites policies and avoid generating excessive load. Please review the terms of use of the sites before use.
> Unauthorized data scraping may lead to legal consequences. Use responsibly.
