import requests
import re
import json

# 'CVE' is passed as a List, elements are of String type
# 'cvss_filter' is passed as a Boolean via Checkbox | unchecked = None / checked = True

def collect_cve_data(CVE, cvss_filter=None):

    CVE_COUNT = len(CVE)
    THRESHOLD = 4  # Established number for which CVEs will be described in detail, above which "bulk" functions will be used

    # ====================================== Function Definitions ======================================

    # API we use:
    # For MITRE CVE database: https://cveawg.mitre.org/api/cve/CVE-XXXX-XXXX}

    # Getting HTML
    def get_html(url):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36'
        }
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f'Error with {url}: {e}')
            return "No data"

    def request(cve):
        url = f'https://cveawg.mitre.org/api/cve/{cve}'
        return get_html(url)

    def request_nvd(cve):
        url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'
        return get_html(url)
        
    # Variable to store rejected CVE numbers
    rejected = None
        
    # Getting CVSS
    def get_CVSS(text, cve=None):
        pattern = r'"baseScore":(.*?),'
        match = re.search(pattern, text)
        if match:
            return float(match.group(1).strip())
        else:
            if cve:
                text2 = request_nvd(cve)
                match = re.search(pattern, text2)
                if match:
                    return float(match.group(1).strip())
                else:
                    return 'No CVSS data'
            else:
                return 'No CVSS data'
        
    # Determining Priority based on CVSS
    def get_priority(cvss):
        if isinstance(cvss, (int, float)):
            if cvss >= 9.0:
                return "Critical"
            elif cvss >= 7.0:
                return "High"
            elif cvss >= 4.0:
                return "Medium"
            elif cvss >= 0.1:
                return "Low"
            else:
                return "No CVSS data"
        return "No CVSS data"

    def get_source(text):
        pattern = r'"references":\[(.*?)\]}]'
        match = re.search(pattern, text)
        if match:
            links = re.findall(r'"(http[s]?://[^"]+)"', match.group(1))
            unique_links = []
            seen = set()
            for link in links:
                if link not in seen:
                    unique_links.append(link)
                    seen.add(link)
            return unique_links if unique_links else 'No source information'
        else:
            pattern_alt = r'"references":\[(.*?)}]'
            match_alt = re.search(pattern_alt, text)
            if match_alt:
                links_alt = re.findall(r'"(http[s]?://[^"]+)"', match_alt.group(1))
                unique_links_alt = []
                seen_alt = set()
                for link in links_alt:
                    if link not in seen_alt:
                        unique_links_alt.append(link)
                        seen_alt.add(link)
                return unique_links_alt if unique_links_alt else 'No source information'
            else:
                return 'No source information'

    def get_description(text):
        pattern = r'"descriptions":\[{"lang":"en","value":"(.*?)"}'
        match = re.search(pattern, text)
        if match:
            return match.group(1).encode().decode('unicode_escape')
        else:
            pattern_alt = r'"descriptions":\[{"value":"(.*?)"'
            match_alt = re.search(pattern_alt, text)
            if match_alt:
                return match_alt.group(1).encode().decode('unicode_escape')
            else:
                return 'No description'

    # **************************************************************************************************        
    def get_version(text, cve):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return "No data about vulnerable versions"

        vulnerable_results = []

        def is_commit_hash(version):
            return bool(re.fullmatch(r"[0-9a-fA-F]{15,}", version))

        cna_section = data.get("containers", {}).get("cna", {})
        vulnerable_list = cna_section.get("affected", [])

        for product in vulnerable_list:
            versions = product.get("versions", [])
            for item in versions:
                version = item.get("version", "").strip()
                if not version:
                    continue
                if is_commit_hash(version):
                    continue

                status = item.get("status", "").strip().lower()
                if status != "affected":
                    continue

                if "lessThanOrEqual" in item:
                    version_to = item.get("lessThanOrEqual", "").strip()
                    if is_commit_hash(version_to):
                        continue
                    if version != "*" and version:
                        vulnerable_results.append(f"Affected from {version} through {version_to}")
                    else:
                        vulnerable_results.append(f"Affected through {version_to}")
                elif "lessThan" in item:
                    version_before = item.get("lessThan", "").strip()
                    if is_commit_hash(version_before):
                        continue
                    vulnerable_results.append(f"Affected before {version_before}")
                else:
                    vulnerable_results.append(f"Affected at {version}")

        vulnerable_results = list(dict.fromkeys(vulnerable_results))
        if vulnerable_results:
            vulnerable_results.append(f"Information about vulnerable versions: https://www.cve.org/CVERecord?id={cve}")
            return "\n".join(vulnerable_results)
        return "No data about vulnerable versions"


    def get_recommendations(text, cve=None):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return "No data about recommended versions"

        unaffected_results = []

        def is_commit_hash(version):
            return bool(re.fullmatch(r"[0-9a-fA-F]{15,}", version))

        cna_section = data.get("containers", {}).get("cna", {})
        vulnerable_list = cna_section.get("affected", [])

        for product in vulnerable_list:
            versions = product.get("versions", [])
            for item in versions:
                if item.get("status", "").strip().lower() != "unaffected":
                    continue

                base_version = item.get("version", "").strip()
                if not base_version or is_commit_hash(base_version):
                    continue

                if "lessThan" in item:
                    version_to = item.get("lessThan", "").strip()
                    if is_commit_hash(version_to):
                        continue
                    unaffected_results.append(f"Unaffected from {base_version} before {version_to}")
                elif "lessThanOrEqual" in item:
                    version_to = item.get("lessThanOrEqual", "").strip()
                    if is_commit_hash(version_to):
                        continue
                    unaffected_results.append(f"Unaffected from {base_version} through {version_to}")
                else:
                    unaffected_results.append(f"Unaffected at {base_version}")

        unaffected_results = list(dict.fromkeys(unaffected_results))
        if unaffected_results:
            return "\n".join(unaffected_results)
        return "No data about recommended versions"

    # ==================================================================================================

    # ======================================= Script Operation ========================================

    # If CVE count is 1 and CVSS filtering is not enabled
    if CVE_COUNT == 1 and cvss_filter == False:

        text = request(CVE[0])

        if text == "No data":
            source = 'No data for the given CVE'
            affected_versions = 'No data for the given CVE'
            recommended_version = 'No data for the given CVE'
            cvss = 'No data for the given CVE'
            priority = 'No data for the given CVE'
            description = 'No data for the given CVE'
            cve = None

        else:
            source = '\n'.join(get_source(text))
            affected_versions = get_version(text, CVE[0])
            recommended_version = get_recommendations(text, CVE[0])
            cvss = get_CVSS(text, CVE[0])
            priority = get_priority(cvss)
            description = get_description(text)
            cve = None

    # If CVE count is 1 and CVSS filtering is enabled
    elif CVE_COUNT == 1 and cvss_filter == True:

        text = request(CVE[0])

        if text == "No data":
            source = 'No data for the given CVE'
            affected_versions = 'No data for the given CVE'
            recommended_version = 'No data for the given CVE'
            cvss = 'No data for the given CVE'
            priority = 'No data for the given CVE'
            description = 'No data for the given CVE'
            cve = None

        else:
            cvss = get_CVSS(text, CVE[0])

            if cvss >= 7:
                source = '\n'.join(get_source(text))
                affected_versions = get_version(text, CVE[0])
                recommended_version = get_recommendations(text, CVE[0])
                priority = get_priority(cvss)
                description = get_description(text)
                
            else:
                source = 'Not checked, CVSS score below 7.0'
                affected_versions = 'Not checked, CVSS score below 7.0'
                recommended_version = 'Not checked, CVSS score below 7.0'
                priority = get_priority(cvss)
                description = 'Not checked, CVSS score below 7.0'
                cve = None

    # If CVE count is in range 2 - [THRESHOLD] and CVSS filtering is not enabled
    elif CVE_COUNT > 1 and CVE_COUNT <= THRESHOLD and cvss_filter == False:
        
        source = []
        affected_versions = []
        recommended_version = []
        cvss = []
        description = []

        cvss_number = []

        for cve_item in CVE:
            text = request(cve_item)

            if text == "No data":
                source.append(f'{cve_item}:\nNo data for the given CVE\n\n')
                affected_versions.append(f'{cve_item}:\nNo data for the given CVE\n\n')
                recommended_version.append(f'{cve_item}:\nNo data for the given CVE\n\n')
                description.append(f'{cve_item}:\nNo data for the given CVE\n\n')

            else:
                source_item = '\n'.join(get_source(text))
                if source_item:
                    source.append(f'{cve_item}:\n{source_item}\n\n')
                else:
                    source.append(f'{cve_item}:\nNo data for the given CVE\n\n')

                affected_versions_item = get_version(text, cve_item)
                if affected_versions_item:
                    affected_versions.append(f'{cve_item}:\n{affected_versions_item}\n\n')
                else:
                    affected_versions.append(f'{cve_item}:\nNo data for the given CVE\n\n')
                
                recommended_version_item = get_recommendations(text, cve_item)
                if recommended_version_item:
                    recommended_version.append(f'{cve_item}:\n{recommended_version_item}\n\n')
                else:
                    recommended_version.append(f'{cve_item}:\nNo data for the given CVE\n\n')

                cvss_item = get_CVSS(text, cve_item)
                if cvss_item:
                    cvss.append(f'{cve_item}: {cvss_item}\n\n')

                    cvss_number.append(float(cvss_item))
                else:
                    cvss.append(f'{cve_item}: No CVSS data for the given CVE\n\n')
                
                description_item = get_description(text)
                if description_item:
                    description.append(f'{cve_item}:\n{description_item}\n\n')
                else:
                    description.append(f'{cve_item}:\nNo data for the given CVE\n\n')

        source = ''.join(source)
        affected_versions = ''.join(affected_versions)
        recommended_version = ''.join(recommended_version)
        description = ''.join(description)
        cvss = ''.join(cvss)

        if cvss_number:
            max_cvss = max(cvss_number)
            priority = get_priority(max_cvss)
        else:
            priority = 'No data for the given CVE'

        cve = None

    # If CVE count is in range 2 - [THRESHOLD] and CVSS filtering is enabled
    elif CVE_COUNT > 1 and CVE_COUNT <= THRESHOLD and cvss_filter == True:

        source = []
        affected_versions = []
        recommended_version = []
        cvss = []
        description = []

        cvss_number = []

        filtered_cve = []
        
        for cve_item in CVE:
            text = request(cve_item)

            if text == "No data":
                source.append(f'{cve_item}:\nNo data for the given CVE\n\n')
                affected_versions.append(f'{cve_item}:\nNo data for the given CVE\n\n')
                recommended_version.append(f'{cve_item}:\nNo data for the given CVE\n\n')
                description.append(f'{cve_item}:\nNo data for the given CVE\n\n')
            else:
                cvss_item = get_CVSS(text, cve_item)
                if cvss_item >= 7.0:
                    cvss.append(f'{cve_item}: {cvss_item}\n\n')
                    cvss_number.append(float(cvss_item))
                    filtered_cve.append(cve_item)

                    source_item = '\n'.join(get_source(text))
                    if source_item:
                        source.append(f'{cve_item}:\n{source_item}\n\n')
                    else:
                        source.append(f'{cve_item}:\nNo data for the given CVE\n\n')

                    affected_versions_item = get_version(text, cve_item)
                    if affected_versions_item:
                        affected_versions.append(f'{cve_item}:\n{affected_versions_item}\n\n')
                    else:
                        affected_versions.append(f'{cve_item}:\nNo data for the given CVE\n\n')
                    
                    recommended_version_item = get_recommendations(text, cve_item)
                    if recommended_version_item:
                        recommended_version.append(f'{cve_item}:\n{recommended_version_item}\n\n')
                    else:
                        recommended_version.append(f'{cve_item}:\nNo data for the given CVE\n\n')

                    description_item = get_description(text)
                    if description_item:
                        description.append(f'{cve_item}:\n{description_item}\n\n')
                    else:
                        description.append(f'{cve_item}:\nNo data for the given CVE\n\n')
        
        if source:
            source = ''.join(source)
        else:
            source = 'Not checked, CVSS score for each CVE is below 7.0'
        
        if affected_versions:
            affected_versions = ''.join(affected_versions)
        else:
            affected_versions = 'Not checked, CVSS score for each CVE is below 7.0'

        if recommended_version:
            recommended_version = ''.join(recommended_version)
        else:
            recommended_version = 'Not checked, CVSS score for each CVE is below 7.0'

        if description:
            description = ''.join(description)
        else:
            description = 'Not checked, CVSS score for each CVE is below 7.0'
        if cvss:
            cvss = ''.join(cvss)
        else:
            cvss = 'CVSS score for each CVE is below 7.0'

        if cvss_number:
            max_cvss = max(cvss_number)
            priority = get_priority(max_cvss)
        else:
            priority = 'No data for the given CVE'

        cve = '\n'.join(filtered_cve)

    # If CVE count is greater than [THRESHOLD] and CVSS filtering is not enabled
    elif CVE_COUNT > THRESHOLD and cvss_filter == False:
        source = []
        affected_versions = []
        recommended_version = []
        cvss = []
        description = []

        rejected = []
        filtered_cve = []

        affected_versions_hashmap = {}
        recommended_version_hashmap = {}
        description_hashmap = {}

        for cve_item in CVE:
            text = request(cve_item)

            if text == "No data":
                rejected.append(cve_item)
            else:
                filtered_cve.append(cve_item)

                source_item = get_source(text)
                if source_item:
                    source.append(f'{cve_item} - {source_item[0]}\n')
                else:
                    source.append(f'{cve_item} - https://www.cve.org/CVERecord?id={cve_item}\n')

                affected_versions_item = get_version(text, cve_item)
                if affected_versions_item and affected_versions_item != 'No data about vulnerable versions':
                    
                    affected_versions_item = '\n'.join(affected_versions_item.splitlines()[:-1])

                    if affected_versions_item not in affected_versions:
                        affected_versions.append(affected_versions_item)

                    if affected_versions_item in affected_versions_hashmap:
                        affected_versions_hashmap[affected_versions_item].append(cve_item)
                    else:
                        affected_versions_hashmap[affected_versions_item] = [cve_item]

                recommended_version_item = get_recommendations(text, cve_item)
                if recommended_version_item and recommended_version_item != 'No data about recommended versions':

                    if recommended_version_item not in recommended_version:
                        recommended_version.append(recommended_version_item)

                    if recommended_version_item in recommended_version_hashmap:
                        recommended_version_hashmap[recommended_version_item].append(cve_item)
                    else:
                        recommended_version_hashmap[recommended_version_item] = [cve_item]

                cvss_item = get_CVSS(text, cve_item)
                if cvss_item and type(cvss_item) == float:
                    cvss.append(cvss_item)

                description_item = get_description(text)
                if description_item and description_item != 'No data about CVE descriptions':

                    if description_item not in description:
                        description.append(description_item)

                    if description_item in description_hashmap:
                        description_hashmap[description_item].append(cve_item)
                    else:
                        description_hashmap[description_item] = [cve_item]

        if affected_versions:
            affected_versions_result = []
            for item in affected_versions:
                temp = ', '.join(affected_versions_hashmap[item])
                affected_versions_result.append(f'{temp}:\n')
                affected_versions_result.append(f'{item}\n\n')
            affected_versions = ''.join(affected_versions_result)
        else:
            affected_versions = 'No data about vulnerable versions for the given CVEs'

        if recommended_version:
            recommended_version_result = []
            for item in recommended_version:
                temp = ', '.join(recommended_version_hashmap[item])
                recommended_version_result.append(f'{temp}:\n')
                recommended_version_result.append(f'{item}\n\n')
            recommended_version = ''.join(recommended_version_result)
        else:
            recommended_version = 'No data about recommended versions for the given CVEs'

        if rejected:
            rejected = '\n'.join(rejected)
        else:
            rejected = None

        if source:
            source = ''.join(source)
        else:
            source = 'No data for the given CVEs'

        if description:
            description_result = []
            for item in description:
                temp = ', '.join(description_hashmap[item])
                description_result.append(f'{temp}:\n')
                description_result.append(f'{item}\n\n')
            description = ''.join(description_result)
        else:
            description = 'Multiple vulnerabilities'

        if cvss:
            min_cvss = min(cvss)
            max_cvss = max(cvss)
            if min_cvss != max_cvss:
                cvss = f'{min_cvss} - {max_cvss}'
            else:
                cvss = f'{max_cvss}'
            priority = get_priority(max_cvss)
        else:
            cvss = 'No data for the given CVEs'
            priority = 'No data for the given CVEs'

        if rejected:
            cve = '\n'.join(filtered_cve)
        else:
            cve = None

    # If CVE count is greater than [THRESHOLD] and CVSS filtering is enabled
    elif CVE_COUNT > THRESHOLD and cvss_filter == True:

        source = []
        affected_versions = []
        recommended_version = []
        cvss = []
        low_cvss = []
        description = []

        affected_versions_hashmap = {}
        recommended_version_hashmap = {}
        description_hashmap = {}

        rejected = []
        filtered_cve = []

        for cve_item in CVE:
            text = request(cve_item)

            if text == "No data":
                rejected.append(cve_item)
            else:
                cvss_item = get_CVSS(text, cve_item)
                if cvss_item and type(cvss_item) == float:
                    if cvss_item >= 7.0:
                        filtered_cve.append(cve_item)
                        cvss.append(float(cvss_item))

                        source_item = get_source(text)
                        if source_item:
                            source.append(f'{cve_item} - {source_item[0]}\n')
                        else:
                            source.append(f'{cve_item} - https://www.cve.org/CVERecord?id={cve_item}\n')

                        affected_versions_item = get_version(text, cve_item)
                        if affected_versions_item and affected_versions_item != 'No data about vulnerable versions':
                            
                            affected_versions_item = '\n'.join(affected_versions_item.splitlines()[:-1])

                            if affected_versions_item not in affected_versions:
                                affected_versions.append(affected_versions_item)

                            if affected_versions_item in affected_versions_hashmap:
                                affected_versions_hashmap[affected_versions_item].append(cve_item)
                            else:
                                affected_versions_hashmap[affected_versions_item] = [cve_item]

                        recommended_version_item = get_recommendations(text, cve_item)
                        if recommended_version_item and recommended_version_item != 'No data about recommended versions':

                            if recommended_version_item not in recommended_version:
                                recommended_version.append(recommended_version_item)

                            if recommended_version_item in recommended_version_hashmap:
                                recommended_version_hashmap[recommended_version_item].append(cve_item)
                            else:
                                recommended_version_hashmap[recommended_version_item] = [cve_item]

                        description_item = get_description(text)
                        if description_item and description_item != 'No data about recommended versions':

                            if description_item not in recommended_version:
                                description.append(description_item)

                            if description_item in description_hashmap:
                                description_hashmap[description_item].append(cve_item)
                            else:
                                description_hashmap[description_item] = [cve_item]
                    else:
                        low_cvss.append(float(cvss_item))

        rejected = '\n'.join(rejected)

        if filtered_cve:
            if source:
                source = ''.join(source)
            else:
                source = 'No data for the given CVEs'

            if affected_versions:
                affected_versions_result = []
                for item in affected_versions:
                    temp = ', '.join(affected_versions_hashmap[item])
                    affected_versions_result.append(f'{temp}:\n')
                    affected_versions_result.append(f'{item}\n\n')
                affected_versions = ''.join(affected_versions_result)
            else:
                affected_versions = 'No data about vulnerable versions for the given CVEs'

            if recommended_version:
                recommended_version_result = []
                for item in recommended_version:
                    temp = ', '.join(recommended_version_hashmap[item])
                    recommended_version_result.append(f'{temp}:\n')
                    recommended_version_result.append(f'{item}\n\n')
                recommended_version = ''.join(recommended_version_result)
            else:
                recommended_version = 'No data about recommended versions for the given CVEs'

            if description:
                description_result = []
                for item in description:
                    temp = ', '.join(description_hashmap[item])
                    description_result.append(f'{temp}:\n')
                    description_result.append(f'{item}\n\n')
                description = ''.join(description_result)
            else:
                description = 'Multiple vulnerabilities'

            if cvss:
                min_cvss = min(cvss)
                max_cvss = max(cvss)
                if min_cvss != max_cvss:
                    cvss = f'{min_cvss} - {max_cvss}'
                else:
                    cvss = f'{max_cvss}'
                priority = get_priority(max_cvss)
            else:
                cvss = 'No data for the given CVEs'
                priority = 'No data for the given CVEs'

        else:
            source = 'Not checked, CVSS score for all CVEs is below 7.0'
            affected_versions = 'Not checked, CVSS score for all CVEs is below 7.0'
            recommended_version = 'Not checked, CVSS score for all CVEs is below 7.0'
            description = 'Not checked, CVSS score for all CVEs is below 7.0'

            if low_cvss:
                min_cvss = min(low_cvss)
                max_cvss = max(low_cvss)
                if min_cvss != max_cvss:
                    cvss = f'{min_cvss} - {max_cvss}'
                else:
                    cvss = f'{max_cvss}'
                    priority = get_priority(max_cvss)
            else:
                cvss = 'Not checked, CVSS score for all CVEs is below 7.0'
                priority = 'Not checked, CVSS score for all CVEs is below 7.0'

        if filtered_cve:
            cve = '\n'.join(filtered_cve)
        else:
            cve = None

    # All other cases
    else:
        source = 'Error in data input, please try again'
        affected_versions = 'Error in data input, please try again'
        recommended_version = 'Error in data input, please try again'
        cvss = 'Error in data input, please try again'
        priority = 'Error in data input, please try again'
        description = 'Error in data input, please try again'

    return(cve, source, affected_versions, recommended_version, cvss, priority, description, rejected)