import requests
import urllib3
import random
import string


# Hide warnings caused by verify=False during controlled HTTPS checks
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_random_path():
    random_name = "".join(
        random.choices(
            string.ascii_letters + string.digits,
            k=20
        )
    )

    return f"/securescan-not-found-{random_name}"


def response_looks_like_baseline(response, baseline):
    """
    Compare a suspected path with a random nonexistent path.

    If both responses look very similar, the website may be
    returning a custom page with HTTP 200 for nonexistent paths.
    """

    if baseline is None:
        return False

    response_text = response.text[:5000].strip()
    baseline_text = baseline.text[:5000].strip()

    # Exact or near-identical responses are likely fake positives
    if response_text == baseline_text:
        return True

    # Compare content length as an additional simple check
    response_length = len(response.content)
    baseline_length = len(baseline.content)

    if baseline_length > 0:

        difference = abs(
            response_length - baseline_length
        )

        percentage_difference = (
            difference / baseline_length
        ) * 100

        # If the response is almost the same size as the
        # random nonexistent page, treat it cautiously
        if percentage_difference < 5:
            return True

    return False


def has_expected_signature(path, response):
    """
    Check whether the returned content resembles the file
    we were actually trying to find.
    """

    content = response.text.strip()
    content_lower = content.lower()

    if path == "/.git/HEAD":

        return (
            content.startswith("ref:")
            and "refs/" in content
        )

    if path == "/.env":

        # Basic environment-variable style detection
        indicators = [
            "db_",
            "database",
            "password=",
            "secret=",
            "api_key",
            "app_key",
            "mail_"
        ]

        return any(
            indicator in content_lower
            for indicator in indicators
        )

    if path == "/robots.txt":

        return (
            "user-agent:" in content_lower
            or "disallow:" in content_lower
            or "allow:" in content_lower
        )

    if path == "/backup.zip":

        # ZIP files normally start with PK
        return response.content.startswith(b"PK")

    if path == "/config.php.bak":

        indicators = [
            "<?php",
            "$",
            "password",
            "database",
            "db_"
        ]

        return any(
            indicator in content_lower
            for indicator in indicators
        )

    return False


def scan_sensitive_paths(target, open_ports):

    findings = []


    sensitive_paths = [

        {
            "path": "/.env",
            "severity": "High",
            "title": "Potential .env File Exposure",
            "description": (
                "A file matching environment configuration "
                "patterns appears to be publicly accessible."
            )
        },

        {
            "path": "/.git/HEAD",
            "severity": "High",
            "title": "Git Repository Exposure",
            "description": (
                "A valid Git HEAD reference appears to be "
                "publicly accessible."
            )
        },

        {
            "path": "/robots.txt",
            "severity": "Info",
            "title": "robots.txt File Accessible",
            "description": (
                "A valid robots.txt file is publicly accessible. "
                "Its contents should be reviewed to ensure it does "
                "not reveal sensitive locations."
            )
        },

        {
            "path": "/backup.zip",
            "severity": "High",
            "title": "Potential Backup File Exposure",
            "description": (
                "A file with a valid ZIP archive signature appears "
                "to be publicly accessible."
            )
        },

        {
            "path": "/config.php.bak",
            "severity": "High",
            "title": "Potential Configuration Backup Exposure",
            "description": (
                "A file resembling a PHP configuration backup "
                "appears to be publicly accessible."
            )
        }

    ]


    for port_info in open_ports:

        service = (
            port_info
            .get("service", "")
            .lower()
        )

        port = port_info.get("port")


        if service not in ["http", "https"]:
            continue


        if service == "https" or port == 443:

            base_url = f"https://{target}"

            if port != 443:
                base_url += f":{port}"

        else:

            base_url = f"http://{target}"

            if port != 80:
                base_url += f":{port}"


        # Create a baseline using a random path that should not exist
        try:

            baseline_url = (
                base_url + get_random_path()
            )

            baseline_response = requests.get(
                baseline_url,
                timeout=8,
                allow_redirects=False,
                verify=False
            )

        except requests.RequestException:

            baseline_response = None


        for path_info in sensitive_paths:

            url = (
                base_url
                + path_info["path"]
            )


            try:

                response = requests.get(
                    url,
                    timeout=8,
                    allow_redirects=False,
                    verify=False
                )


                # Only investigate successful responses
                if response.status_code != 200:
                    continue


                # Ignore pages that resemble the random
                # nonexistent-path response
                if response_looks_like_baseline(
                    response,
                    baseline_response
                ):
                    continue


                # Verify that the returned content actually
                # resembles the expected file
                if not has_expected_signature(
                    path_info["path"],
                    response
                ):
                    continue


                findings.append({

                    "severity":
                        path_info["severity"],

                    "title":
                        path_info["title"],

                    "description":
                        path_info["description"]
                        + f" Accessible path: "
                        + path_info["path"],

                    "port":
                        port,

                    "why_it_matters":
                        "Publicly accessible files can reveal "
                        "information about the web application "
                        "or its configuration.",

                    "possible_impact":
                        "Depending on the file contents, exposed "
                        "information could assist unauthorized "
                        "access or further attacks.",

                    "recommended_fix":
                        "Review web-server access controls and "
                        "ensure sensitive files are stored outside "
                        "the publicly accessible web directory."

                })


            except requests.RequestException:

                continue


    return findings