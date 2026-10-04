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


def scan_http_methods(target, open_ports):

    findings = []

    risky_methods = {

        "TRACE": {
            "severity": "Medium",
            "description": (
                "The HTTP TRACE method appears to be enabled. "
                "Review whether it is required and disable it "
                "if unnecessary."
            )
        },

        "PUT": {
            "severity": "High",
            "description": (
                "The HTTP PUT method appears to be enabled. "
                "Verify that authentication and authorization "
                "controls prevent unauthorized modification."
            )
        },

        "DELETE": {
            "severity": "High",
            "description": (
                "The HTTP DELETE method appears to be enabled. "
                "Ensure destructive operations require proper "
                "authentication and authorization."
            )
        },

        "CONNECT": {
            "severity": "Medium",
            "description": (
                "The HTTP CONNECT method appears to be enabled. "
                "Review whether proxy or tunneling functionality "
                "is intentionally exposed."
            )
        }

    }


    reported_methods = set()


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

            response = requests.options(
                url,
                timeout=10,
                allow_redirects=True,
                verify=False
            )


            # Only trust a successful OPTIONS response
            if response.status_code >= 400:
                continue


            allowed_methods = response.headers.get(
                "Allow",
                ""
            )


            if not allowed_methods:
                continue


            methods = {

                method
                .strip()
                .upper()

                for method in allowed_methods.split(",")

                if method.strip()

            }


            for method, info in risky_methods.items():

                # Avoid duplicate findings across
                # HTTP and HTTPS endpoints
                if method in reported_methods:
                    continue


                if method in methods:

                    findings.append({

                        "severity":
                            info["severity"],

                        "title":
                            f"HTTP {method} Method Enabled",

                        "description":
                            info["description"],

                        "port":
                            port

                    })


                    reported_methods.add(
                        method
                    )


        except requests.RequestException:

            continue


    return findings