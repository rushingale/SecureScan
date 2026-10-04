import ipaddress
import re


def validate_target(target):
    target = target.strip()

    # Check if target is a valid IP address
    try:
        ipaddress.ip_address(target)
        return {
            "valid": True,
            "type": "IP Address",
            "target": target
        }

    except ValueError:
        pass

    # Check if target is a valid hostname/domain
    hostname_pattern = r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    if re.match(hostname_pattern, target):
        return {
            "valid": True,
            "type": "Hostname",
            "target": target
        }

    return {
        "valid": False,
        "type": None,
        "target": target,
        "message": "Invalid IP address or hostname"
    }