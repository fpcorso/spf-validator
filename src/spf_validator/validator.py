import re
from urllib.parse import urlparse

import dns.resolver


def validate_domain_spf(domain: str) -> list[str]:
    """Validate the SPF record for a domain.

    Args:
        domain: The domain to validate the SPF record for.

    Returns:
        A list of issues with the SPF record. If the list is empty, the SPF record is valid.
    """

    issues = []

    spf = get_domain_spf_record(domain)

    # If we didn't find an SPF record, go ahead and bail now.
    if not spf:
        issues.append("This domain does not have an SPF record.")
        return issues

    issues.extend(validate_spf_string(spf))

    return issues


def validate_spf_string(spf: str) -> list[str]:
    """Validate an SPF string.

    Args:
        spf: The SPF string to validate.

    Returns:
        A list of issues with the SPF string. If the list is empty, the SPF string is valid.
    """

    # If the string is empty, go ahead and bail now.
    if not spf:
        return ["Empty SPF string."]

    issues = []

    version_regex = re.compile(r"\bv=\S+\b")
    version_instances = version_regex.findall(spf)

    # First, make sure we are not missing the version instance.
    if len(version_instances) == 0:
        issues.append(
            "The SPF record is missing the SPF version. This should be at the beginning of the record and look like v=spf1"
        )

    # Next, make sure we only have 1 version instance.
    if len(version_instances) > 1:
        issues.append(
            "There are more than one instance of the SPF version in this SPF record."
        )

    # Next, make sure the version instance is at the beginning of the string.
    if version_regex.search(spf).span()[0] != 0:
        issues.append("The SPF version is not at the beginning of the SPF record.")

    catchall_regex = re.compile(r"\S?all\b")
    catchall_instances = catchall_regex.findall(spf)

    # Next, make sure we have at least 1 catchall instance.
    if len(catchall_instances) == 0:
        issues.append(
            "There is not a catchall in this SPF record. There should be an 'all' at the end of the record."
        )

    # Next, make sure we only have 1 catchall instance.
    if len(catchall_instances) > 1:
        issues.append("There is more than one catchall in this SPF record.")

    catchall_instance = catchall_regex.search(spf)

    # Next, make sure the catchall instance is at the end of the string.
    if catchall_instance.span()[1] != len(spf):
        issues.append("The catchall is not at the end of the SPF record.")

    # Next, make sure the catchall is not prefixed with a + qualifier.
    if catchall_instance.group()[0] == "+" or catchall_instance.group()[0] == "a":
        issues.append(
            "The catchall is prefixed with + qualifier. This means that the SPF record will always pass. This is not recommended."
        )

    return issues


def get_domain_spf_record(domain: str) -> str:
    """Get the SPF record for a domain.

    Args:
        domain: The domain to get the SPF record for.

    Returns:
        The SPF record for the domain.
    """
    # If domain is a URL, remove protocol, paths, and ports from it.
    if "://" in domain:
        domain = urlparse(domain).hostname

    # Remove www subdomain (if present)
    if domain.startswith("www."):
        domain = domain[4:]

    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
    except dns.resolver.NoAnswer:
        return ""

    # Loop through the records and find the SPF record.
    for record in txt_records:
        record_text = record.strings[0].decode("utf-8")
        if "v=spf" in record_text or "all" in record_text:
            return record_text

    # If we get here, we didn't find an SPF record.
    return ""
