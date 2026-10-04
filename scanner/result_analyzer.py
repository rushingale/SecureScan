import re


def extract_cve_references(script_output):
    """
    Extract CVE IDs and CVSS scores from Nmap Vulners output.

    Returns data like:
    [
        {
            "cve": "CVE-2026-44400",
            "cvss": 9.8,
            "severity": "Critical"
        }
    ]
    """

    cve_pattern = re.compile(
        r"(CVE-\d{4}-\d+)\s+([0-9]+(?:\.[0-9]+)?)",
        re.IGNORECASE
    )

    matches = cve_pattern.findall(script_output)

    cves = []

    seen = set()

    for cve_id, score_text in matches:

        cve_id = cve_id.upper()

        if cve_id in seen:
            continue

        seen.add(cve_id)

        try:
            score = float(score_text)
        except ValueError:
            continue

        if score >= 9.0:
            severity = "Critical"

        elif score >= 7.0:
            severity = "High"

        elif score >= 4.0:
            severity = "Medium"

        elif score > 0:
            severity = "Low"

        else:
            severity = "Info"

        cves.append({
            "cve": cve_id,
            "cvss": score,
            "severity": severity,
            "reference": (
                f"https://vulners.com/cve/{cve_id}"
            )
        })

    # Sort highest score first
    cves.sort(
        key=lambda item: item["cvss"],
        reverse=True
    )

    return cves


def get_highest_cve_severity(cves):
    """
    Determine severity from the highest CVSS score.
    """

    if not cves:
        return "Medium"

    highest_score = cves[0]["cvss"]

    if highest_score >= 9.0:
        return "Critical"

    elif highest_score >= 7.0:
        return "High"

    elif highest_score >= 4.0:
        return "Medium"

    elif highest_score > 0:
        return "Low"

    return "Info"


def analyze_scan(scan_result):

    findings = []
    open_ports = []
    closed_ports = []

    if not scan_result.get("success"):

        return {
            "success": False,
            "error": scan_result.get(
                "error",
                "Scan failed"
            )
        }

    for host in scan_result.get("results", []):

        # ==========================================
        # PORT AND SERVICE ANALYSIS
        # ==========================================

        for protocol, ports in host.get(
            "protocols",
            {}
        ).items():

            for port_info in ports:

                port = port_info.get("port")
                state = port_info.get("state", "")
                service = port_info.get("service", "")

                if state == "open":

                    open_ports.append({
                        "port": port,
                        "protocol": protocol,
                        "service": service,
                        "product": port_info.get(
                            "product",
                            ""
                        ),
                        "version": port_info.get(
                            "version",
                            ""
                        )
                    })

                    # FTP
                    if port == 21:

                        findings.append({
                            "severity": "Medium",
                            "title": "FTP Port 21 Open",
                            "description": (
                                "Port 21 (FTP) is open. "
                                "Traditional FTP may transmit usernames, "
                                "passwords, and data without encryption."
                            ),
                            "port": port,
                            "source": "Port Analysis"
                        })

                    # Telnet
                    elif port == 23:

                        findings.append({
                            "severity": "High",
                            "title": "Telnet Port 23 Open",
                            "description": (
                                "Port 23 (Telnet) is open. "
                                "Telnet transmits communication "
                                "without encryption."
                            ),
                            "port": port,
                            "source": "Port Analysis"
                        })

                    # SMB
                    elif port == 445:

                        findings.append({
                            "severity": "Medium",
                            "title": "SMB Port 445 Open",
                            "description": (
                                "Port 445 is open and SMB services "
                                "are accessible. Ensure SMB is properly "
                                "configured and not unnecessarily exposed."
                            ),
                            "port": port,
                            "source": "Port Analysis"
                        })

                    # RDP
                    elif port == 3389:

                        findings.append({
                            "severity": "Medium",
                            "title": "RDP Port 3389 Open",
                            "description": (
                                "Port 3389 (Remote Desktop Protocol) "
                                "is open. Use strong authentication "
                                "and restrict unnecessary access."
                            ),
                            "port": port,
                            "source": "Port Analysis"
                        })

                elif state == "closed":

                    closed_ports.append({
                        "port": port,
                        "protocol": protocol,
                        "service": service
                    })

        # ==========================================
        # NMAP NSE RESULTS
        # ==========================================

        vulnerabilities = host.get(
            "vulnerabilities",
            []
        )

        for vulnerability in vulnerabilities:

            script_name = vulnerability.get(
                "script",
                "Unknown Nmap Script"
            )

            script_output = vulnerability.get(
                "output",
                ""
            )

            port = vulnerability.get(
                "port"
            )

            if not script_output:
                continue

            output_lower = script_output.lower()
            script_lower = script_name.lower()

            # ======================================
            # IGNORE NEGATIVE / FAILED RESULTS
            # ======================================

            negative_indicators = [
                "couldn't find any",
                "could not find any",
                "no vulnerabilities found",
                "no vulnerability found",
                "not vulnerable",
                "script execution failed",
                "error: script execution failed"
            ]

            if any(
                indicator in output_lower
                for indicator in negative_indicators
            ):
                continue

            # ======================================
            # SPECIAL HANDLING FOR VULNERS
            # ======================================

            if script_lower == "vulners":

                cves = extract_cve_references(
                    script_output
                )

                if not cves:
                    continue

                severity = get_highest_cve_severity(
                    cves
                )

                highest = cves[0]

                findings.append({
                    "severity": severity,

                    "title": (
                        "Potential CVE References "
                        "for Detected Software"
                    ),

                    "description": (
                        f"Nmap Vulners matched "
                        f"{len(cves)} CVE reference(s) "
                        f"to the detected software/version. "
                        f"The highest referenced CVSS score is "
                        f"{highest['cvss']} "
                        f"({highest['cve']}). "
                        f"These references require manual "
                        f"verification before being treated "
                        f"as confirmed vulnerabilities."
                    ),

                    "port": (
                        port if port else "Host"
                    ),

                    "source": (
                        "Nmap NSE - Vulners"
                    ),

                    "script": script_name,

                    "cves": cves,

                    "verification_status": (
                        "Potential / Requires Verification"
                    )
                })

                continue

            # ======================================
            # OTHER NSE VULNERABILITY RESULTS
            # ======================================

            positive_indicators = [
                "vulnerable:",
                "likely vulnerable",
                "state: vulnerable",
                "state: likely vulnerable",
                "security issue",
                "known vulnerability",
                "cve-"
            ]

            if not any(
                indicator in output_lower
                for indicator in positive_indicators
            ):
                continue

            severity = "Medium"

            if (
                "vulnerable:" in output_lower
                or "likely vulnerable" in output_lower
                or "state: vulnerable" in output_lower
                or "state: likely vulnerable" in output_lower
                or "remote code execution" in output_lower
            ):
                severity = "High"

            if any(
                keyword in script_lower
                for keyword in [
                    "heartbleed",
                    "ms17",
                    "eternalblue",
                    "shellshock",
                    "poodle"
                ]
            ):
                severity = "High"

            findings.append({
                "severity": severity,

                "title": (
                    f"Nmap Vulnerability Detection: "
                    f"{script_name}"
                ),

                "description": script_output,

                "port": (
                    port if port else "Host"
                ),

                "script": script_name,

                "source": (
                    "Nmap NSE Vulnerability Script"
                )
            })

    return {
        "success": True,

        "summary": {
            "open_ports": len(open_ports),
            "closed_ports": len(closed_ports),
            "findings": len(findings)
        },

        "open_ports": open_ports,

        "findings": findings
    }