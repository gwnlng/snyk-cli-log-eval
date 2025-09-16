import sys
import json


def get_trailing_string_find(line: str, substring: str) -> str:
    """
    Returns trailing string of line after first occurrence of the substring
    Returns empty string if not found.
    :param line: Line
    :param substring: Substring
    :return: trailing string if found, empty string otherwise
    """
    start_index = line.find(substring)
    if start_index != -1:  # Check if the substring was found
        # Slice from the character right after the substring
        return line[start_index + len(substring):]
    else:
        return ""  # Substring not found


def extract_metadata_by_prefix(prefix: str) -> dict:
    """
    Reads lines from standard input and extract first occurring line that contains a specified prefix.
    It then slices off prefix, extracting trailing string as a metadata JSON
    :param prefix: prefix string
    :return: json
    """
    duration_ms_prefix = '"durationMs": '
    scanned_projects_prefix = '"scannedProjects": '
    scanned_projects_json_property = "legacycli::metadata__allProjects__scannedProjects"
    duration_ms = 0
    scanned_projects = 0
    invalid_metadata = False
    metadata_json = {}
    analytics_metadata = ""
    # Read input line by line from stdin
    for line in sys.stdin:
        # .strip() removes leading/trailing whitespace, including newline characters,
        # ensuring a clean match against the prefix.
        if prefix in line.strip():
            try:
                analytics_metadata = get_trailing_string_find(line.strip(), prefix)
                # snyk version 1.1297.3 returns invalid json ending with branch=***
                if analytics_metadata.endswith("***"):
                    invalid_metadata = True
                    analytics_metadata = analytics_metadata + '"}}}}}'

                # handle non-sensitive sanitized substring containing ****
                if "****" in analytics_metadata:
                    analytics_metadata = analytics_metadata.replace("****", "data")

                metadata_json = json.loads(analytics_metadata)
                # print(f"json: {metadata_json}")
            except json.JSONDecodeError as e:
                print(f"Error at decoding analytics metadata line: {analytics_metadata} at position: {e.pos}")
            # exit the stdin filtering
            break
        elif duration_ms_prefix in line.strip():
            # handle potential Snyk CLI 1.1297.3 invalid metadata analytics json with durationMs property matching
            raw_duration_ms = get_trailing_string_find(line.strip(), duration_ms_prefix)
            # remove the trailing comma
            duration_ms = int(raw_duration_ms[:-1])
        elif scanned_projects_prefix in line.strip():
            # handle potential Snyk CLI 1.1297.3 invalid metadata analytics json with scannedProjects property matching
            raw_scanned_projects = get_trailing_string_find(line.strip(), scanned_projects_prefix)
            # remove the trailing comma
            scanned_projects = int(raw_scanned_projects[:-1])

    # remove following if-check once Snyk CLI returns valid metadata analytics JSON
    if invalid_metadata:
        # insert the duration_ms property into the metadata json
        runtime_perf_duration = {"runtime": {"performance": {"duration_ms": duration_ms}}}
        metadata_json["data"]["attributes"].update(runtime_perf_duration)
        # insert the scannedProjects property into the metadata json

    if scanned_projects_json_property not in metadata_json["data"]["attributes"]["interaction"]["extension"]:
        all_scanned_projects = {scanned_projects_json_property: scanned_projects}
        metadata_json["data"]["attributes"]["interaction"]["extension"].update(all_scanned_projects)

    return metadata_json


def eval_manifests(complete, partial, manifest_files) -> dict:
    """
    Evaluates measurement of manifests by finding all elements missing from 'complete' that are not in 'partial',
    assuming 'partial' is a strict subsequence of 'complete' i.e. manifests skipped,
    relative order of scanned manifests is preserved.
    :param complete: Complete list of package managers
    :param partial: Partial scanned list of package managers
    :param manifest_files: Manifest target files (path)
    :return: Dictionary of measurements of scanned and skipped manifests
    """
    scanned_manifests = []
    skipped_manifests = []
    partial_idx = 0

    for complete_idx, complete_item in enumerate(complete):
        if partial_idx < len(partial) and complete_item == partial[partial_idx]:
            # This item matches in sequence, so it is scanned
            scanned_manifests.append(manifest_files[complete_idx])
            partial_idx += 1
        else:
            # This item from the complete list was skipped in the partial list
            skipped_manifests.append(manifest_files[complete_idx])

    error_indicator = True if skipped_manifests else False
    error_message = f"{len(skipped_manifests)}/{len(complete)} manifests encountered error at dependency resolution" if error_indicator else ""
    manifest_measurements = {
        "scanned_manifests": scanned_manifests,
        "skipped_manifests": skipped_manifests,
        "error_indicator": error_indicator,
        "error_message": error_message
    }
    return manifest_measurements


def deduplicate_multi_project_manifest(package_managers) -> list:
    """
    Deduplicates only first occurring matching element on list i.e. multi-project package manager e.g. Gradle.
    If the first element appears elsewhere in the list, those subsequent occurrences are removed.
    The rest of the list remains unchanged.
    :param package_managers: package managers (list)
    :return: deduplicated package managers (list)
    """
    if not package_managers:
        return []

    # Step 1: Find the first element that is duplicated
    # iterate and see whether gradle is used
    seen_elements = set()
    first_multi_project_pm = None
    gradle_pm = "gradle"

    for item in package_managers:
        if item in seen_elements and item == gradle_pm:
            first_multi_project_pm = item
            break  # Found the target, stop searching
        seen_elements.add(item)

    # If no element was duplicated, return the original list
    if first_multi_project_pm is None:
        return list(package_managers) # Return a copy to be safe

    # Step 2: Build the new list, deduplicating only the identified element
    deduplicated_list = []
    # Flag to ensure we keep only the first occurrence of the target element
    kept_first_occurrence_of_pm = False

    for item in package_managers:
        if item == first_multi_project_pm:
            if not kept_first_occurrence_of_pm:
                # Keep the very first occurrence of the identified duplicated element
                deduplicated_list.append(item)
                kept_first_occurrence_of_pm = True
        else:
            # For all other elements, just append them as they are
            deduplicated_list.append(item)

    return deduplicated_list


def eval_manifests_metadata(metadata_json: dict):
    """
    Evaluates scan manifests metadata.
    :param: metadata_json (Dict)
    :return: manifest_measurements (Dict)
    """
    # check whether it is complete or partial manifest scan
    all_projects_package_managers = metadata_json['legacycli::metadata__allProjects__packageManagers']
    package_managers = all_projects_package_managers.strip("[]").split()
    all_projects_target_files = metadata_json['legacycli::metadata__allProjects__targetFiles']
    target_files = all_projects_target_files.strip("[]").split()
    scanned_projects = metadata_json['legacycli::metadata__allProjects__scannedProjects']
    multi_project_build = True if scanned_projects > len(target_files) else False

    # compute measurements of cli processed manifests files (paths)
    metadata_package_manager = metadata_json['legacycli::metadata__packageManager']
    scanned_package_managers = metadata_package_manager.strip("[]").split()
    if not multi_project_build:
        manifest_measurements = eval_manifests(package_managers, scanned_package_managers, target_files)
    else:
        # certain configurations to snyk gradle plugin return only the root build.gradle in the targetFiles property
        # yet scanned package managers indicate multiple occurrences of gradle build manifests
        # so deduplicate first multi-project package manager type on the list. This is not foolproof
        dedup_scanned_package_managers = deduplicate_multi_project_manifest(scanned_package_managers)
        manifest_measurements = eval_manifests(package_managers, dedup_scanned_package_managers, target_files)

    # print(manifest_measurements)
    return manifest_measurements


def eval_scan_status(exit_code: int, error_at_manifest_scan: bool) -> str:
    """
    Evaluates scan status based on the snyk cli exit code with skipped manifests indicator
    :param exit_code: cli exit code
    :param error_at_manifest_scan: whether error at manifests scan (bool)
    :return: status
    """
    if exit_code == 0 or exit_code == 1:
        if error_at_manifest_scan:
            status = "failure"
        else:
            status = "success"
    else:
        status = "failure"

    return status


def eval_cli_metadata(metadata_json) -> dict:
    """
    Evaluates raw cli analytics metadata json and formats required info into a dictionary
    :param metadata_json:
    :return: scan_results (Dict)
    """
    scan_results = {}
    error_indicator = False

    try:
        extension_obj = metadata_json['data']['attributes']['interaction']['extension']
        exitcode = extension_obj['exitcode']
        # refer to https://docs.snyk.io/snyk-cli/commands/test#exit-codes
        if exitcode < 2:
            # scan is completed, check the manifests metadata of scan
            manifest_measurements = eval_manifests_metadata(extension_obj)
            error_indicator = manifest_measurements['error_indicator']
            scan_results.update(manifest_measurements)
        elif exitcode == 2:
            # scan returns error during scan
            error_message = "error at snyk test cli execution, examine the debug logs"
            scan_results["error_message"] = error_message
        elif exitcode == 3:
            error_message = "failure due to no supported manifests detected"
            scan_results["error_message"] = error_message

        # evaluates scan status success if all manifests successfully scanned, failure otherwise
        scan_status = eval_scan_status(exitcode, error_indicator)
        # Temporarily disable duration metric on snyk 1.1297.3 broken JSON
        scan_duration_ms = 0
        if "runtime" in metadata_json['data']['attributes']:
            scan_duration_ms = metadata_json['data']['attributes']['runtime']['performance']['duration_ms']
        # enrich the scan results data
        scan_results["status"] = scan_status
        scan_results["duration_sec"] = scan_duration_ms / 1000
        return scan_results
    except KeyError as e:
        print(f"Error at retrieving key from cli metadata json: {e}")
        print(f"Ensure snyk cli cmd includes --all-projects --debug")
        return {}


if __name__ == "__main__":
    analytics_prefix = "analytics.report:2 - [0] Data: "
    metadata = extract_metadata_by_prefix(analytics_prefix)
    if metadata:
        metadata_summary = eval_cli_metadata(metadata)
        # prints a pretty summary json
        ms_json = json.dumps(metadata_summary, indent=2)
        print(ms_json)
    else:
        print(f"Error at retrieving cli scan metadata line")
        sys.exit(1)
