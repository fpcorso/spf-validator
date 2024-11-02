import ipaddress
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
        return ["The SPF record is empty."]

    issues = []

    ###
    # General checks
    ###
    if len(spf) > 255:
        issues.append(
            "The SPF record is longer than 255 characters which is not allowed."
        )

    ###
    # SPF version checks
    ###

    version_regex = re.compile(r"\bv=\w+\s")
    version_instances = version_regex.findall(spf)

    if len(version_instances) == 0:
        issues.append(
            "The SPF record is missing the SPF version. This should be at the beginning of the record and look like v=spf1"
        )
    else:
        if len(version_instances) > 1:
            issues.append(
                "There are more than one instance of the SPF version in this SPF record."
            )

        if len(version_instances) > 0 and version_regex.search(spf).span()[0] != 0:
            issues.append("The SPF version is not at the beginning of the SPF record.")

    ###
    # Catchall checks
    ###

    catchall_regex = re.compile(r"\s[~\+\-\?]?all\b")
    catchall_instances = catchall_regex.findall(spf)
    print(catchall_instances)

    if len(catchall_instances) == 0:
        issues.append(
            "There is not a catchall in this SPF record. There should be an 'all' at the end of the record."
        )
    else:
        if len(catchall_instances) > 1:
            issues.append("There is more than one catchall in this SPF record.")

        catchall_instance = catchall_regex.search(spf)

        if catchall_instance.span()[1] != len(spf):
            issues.append("The catchall is not at the end of the SPF record.")

        catchall = catchall_instance.group().strip()
        if catchall[0] in ["+", "a"]:
            issues.append(
                "The catchall is prefixed with + qualifier. This means that the SPF record will always pass which allows anyone to send emails claiming to be from you. This is not recommended."
            )

    ###
    # IP4 and IP6 checks
    ###

    ip4_regex = re.compile(r"\bip4:\S+\b")
    ip6_regex = re.compile(r"\bip6:\S+\b")
    ip_instances = ip4_regex.findall(spf) + ip6_regex.findall(spf)
    for ip4_instance in ip_instances:
        # Strip off the ip4: or ip6: prefix
        ip = ip4_instance[4:]
        if "/" not in ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                issues.append(f"The IP {ip} is not valid.")
        else:
            try:
                ipaddress.ip_network(ip)
            except ValueError:
                issues.append(f"The IP {ip} is not valid.")

    ###
    # Deprecated mechanism checks
    ###

    ptr_regex = re.compile(r"\bptr:?(\S+)?\b")
    ptr_instances = ptr_regex.findall(spf)
    if len(ptr_instances) > 0:
        issues.append(
            "The SPF record contains the 'ptr' mechanism which is not longer in the SPF specification and can result in a larger number of expensive DNS lookups."
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
        # Convert the record to a string.
        record_text = "".join([a.decode("utf-8") for a in record.strings])
        if "v=spf" in record_text:
            return record_text

    # If we get here, we didn't find an SPF record.
    return ""
