import requests
import urllib3


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


def build_url(target, service, port):

    if service == "https" or port == 443:

        if port == 443:
            return f"https://{target}"

        return f"https://{target}:{port}"

    if port == 80:
        return f"http://{target}"

    return f"http://{target}:{port}"


def scan_http_headers(target, open_ports):

    findings = []

    # Prevent the same header issue from being
    # reported repeatedly across HTTP/HTTPS endpoints
    reported_headers = set()


    for port_info in open_ports:

        service = (
            port_info
            .get("service", "")
            .lower()
        )

        port = port_info.get("port")


        if service not in ["http", "https"]:
            continue


        url = build_url(
            target,
            service,
            port
        )


        try:

            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                verify=False
            )


            headers = response.headers


            # These headers can be useful on HTTP or HTTPS
            security_headers = {

                "Content-Security-Policy": {
                    "severity": "Medium",
                    "description": (
                        "Content-Security-Policy is missing. "
                        "The application has less browser-side "
                        "control over which content can be loaded."
                    )
                },

                "X-Frame-Options": {
                    "severity": "Medium",
                    "description": (
                        "X-Frame-Options is missing. "
                        "The application may have reduced "
                        "protection against clickjacking."
                    )
                },

                "X-Content-Type-Options": {
                    "severity": "Low",
                    "description": (
                        "X-Content-Type-Options is missing. "
                        "Browsers may perform MIME-type sniffing."
                    )
                },

                "Referrer-Policy": {
                    "severity": "Low",
                    "description": (
                        "Referrer-Policy is missing. "
                        "More referrer information than necessary "
                        "may be shared during navigation."
                    )
                }

            }


            # HSTS should only be checked when the
            # final connection is actually HTTPS
            if response.url.startswith("https://"):

                security_headers[
                    "Strict-Transport-Security"
                ] = {

                    "severity": "Medium",

                    "description": (
                        "Strict-Transport-Security is missing. "
                        "Browsers may not be instructed to "
                        "automatically enforce HTTPS connections."
                    )

                }


            for header, info in security_headers.items():

                # Prevent duplicate findings for the
                # same missing security header
                if header in reported_headers:
                    continue


                if header not in headers:

                    findings.append({

                        "severity":
                            info["severity"],

                        "title":
                            f"Missing {header}",

                        "description":
                            info["description"],

                        "port":
                            port

                    })


                    reported_headers.add(
                        header
                    )


        except requests.RequestException:

            # Do not create a security finding simply
            # because an HTTP request failed.
            # The scan continues with other services.
            continue


    return findings