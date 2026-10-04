import socket
import ssl
from datetime import datetime, timezone


def scan_ssl_certificate(target, open_ports):
    findings = []

    # Look for HTTPS services
    for port_info in open_ports:

        service = port_info.get("service", "").lower()
        port = port_info.get("port")

        # Only check HTTPS ports/services
        if service != "https" and port != 443:
            continue

        try:
            context = ssl.create_default_context()

            with socket.create_connection(
                (target, port),
                timeout=10
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=target
                ) as secure_socket:

                    certificate = secure_socket.getpeercert()

            # Get certificate expiry date
            expiry_date_string = certificate.get("notAfter")

            if expiry_date_string:

                expiry_date = datetime.strptime(
                    expiry_date_string,
                    "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)

                current_date = datetime.now(timezone.utc)

                days_remaining = (
                    expiry_date - current_date
                ).days

                # Certificate already expired
                if days_remaining < 0:

                    findings.append({
                        "severity": "High",
                        "title": "Expired SSL/TLS Certificate",
                        "description": (
                            f"The SSL/TLS certificate expired "
                            f"{abs(days_remaining)} days ago."
                        ),
                        "port": port
                    })

                # Certificate expiring soon
                elif days_remaining <= 30:

                    findings.append({
                        "severity": "Medium",
                        "title": "SSL/TLS Certificate Expiring Soon",
                        "description": (
                            f"The SSL/TLS certificate will expire "
                            f"in {days_remaining} days."
                        ),
                        "port": port
                    })

        except ssl.SSLCertVerificationError:

            findings.append({
                "severity": "High",
                "title": "SSL/TLS Certificate Verification Failed",
                "description": (
                    "The HTTPS service presented a certificate "
                    "that could not be verified."
                ),
                "port": port
            })

        except (socket.timeout, socket.error, ssl.SSLError) as error:

            findings.append({
                "severity": "Info",
                "title": f"SSL/TLS Check Failed on Port {port}",
                "description": (
                    f"Could not complete the SSL/TLS check: "
                    f"{str(error)}"
                ),
                "port": port
            })

    return findings