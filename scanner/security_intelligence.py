def enrich_findings(findings):

    for finding in findings:

        title = finding.get("title", "").lower()
        severity = finding.get("severity", "").lower()

        # Default intelligence
        intelligence = {
            "why_it_matters": (
                "This security issue may increase the attack surface "
                "of the target system."
            ),
            "possible_impact": (
                "A security weakness or misconfiguration may increase "
                "the risk of unauthorized access or unintended behavior."
            ),
            "recommended_fix": (
                "Review the configuration, restrict unnecessary access, "
                "and apply appropriate security controls."
            )
        }

        # --------------------------------------------------
        # FTP
        # --------------------------------------------------
        if "ftp" in title or finding.get("port") == 21:

            intelligence = {
                "why_it_matters": (
                    "Traditional FTP may transmit usernames, passwords, "
                    "and transferred data without encryption."
                ),
                "possible_impact": (
                    "Credentials or sensitive data could potentially be "
                    "intercepted on an untrusted network."
                ),
                "recommended_fix": (
                    "Use SFTP or FTPS instead of traditional FTP and "
                    "disable anonymous access unless explicitly required."
                )
            }

        # --------------------------------------------------
        # SMB
        # --------------------------------------------------
        elif "smb" in title or finding.get("port") == 445:

            intelligence = {
                "why_it_matters": (
                    "SMB provides file and printer sharing and can increase "
                    "the network attack surface when unnecessarily exposed."
                ),
                "possible_impact": (
                    "Unauthorized users may attempt to access shared "
                    "resources or exploit weaknesses in the SMB service."
                ),
                "recommended_fix": (
                    "Disable SMB if it is not required, restrict access to "
                    "trusted networks, and keep the SMB service updated."
                )
            }

        # --------------------------------------------------
        # TELNET
        # --------------------------------------------------
        elif "telnet" in title or finding.get("port") == 23:

            intelligence = {
                "why_it_matters": (
                    "Telnet does not encrypt communication between the "
                    "client and server."
                ),
                "possible_impact": (
                    "Credentials and commands could potentially be "
                    "intercepted on an untrusted network."
                ),
                "recommended_fix": (
                    "Disable Telnet and use SSH for secure remote access."
                )
            }

        # --------------------------------------------------
        # RDP
        # --------------------------------------------------
        elif "rdp" in title or finding.get("port") == 3389:

            intelligence = {
                "why_it_matters": (
                    "Remote Desktop Protocol provides direct remote access "
                    "to a system and should not be unnecessarily exposed."
                ),
                "possible_impact": (
                    "Weak authentication or poor access controls could "
                    "increase the risk of unauthorized access attempts."
                ),
                "recommended_fix": (
                    "Restrict RDP to trusted networks, use strong "
                    "authentication, enable Network Level Authentication, "
                    "and consider VPN-based access."
                )
            }

        # --------------------------------------------------
        # CONTENT SECURITY POLICY
        # --------------------------------------------------
        elif "content-security-policy" in title:

            intelligence = {
                "why_it_matters": (
                    "A Content Security Policy helps control which sources "
                    "of scripts, styles, and other resources a browser "
                    "is allowed to load."
                ),
                "possible_impact": (
                    "Without a properly configured policy, certain "
                    "client-side attacks such as script injection may "
                    "have fewer browser-side restrictions."
                ),
                "recommended_fix": (
                    "Configure a Content-Security-Policy header based on "
                    "the application's required scripts, styles, and "
                    "trusted resource sources."
                )
            }

        # --------------------------------------------------
        # X-FRAME-OPTIONS
        # --------------------------------------------------
        elif "x-frame-options" in title:

            intelligence = {
                "why_it_matters": (
                    "X-Frame-Options helps protect web pages from being "
                    "embedded inside unauthorized frames."
                ),
                "possible_impact": (
                    "The application may have reduced protection against "
                    "clickjacking attacks that attempt to trick users "
                    "into interacting with hidden or misleading content."
                ),
                "recommended_fix": (
                    "Configure X-Frame-Options as DENY or SAMEORIGIN, "
                    "or use the Content-Security-Policy frame-ancestors "
                    "directive where appropriate."
                )
            }

        # --------------------------------------------------
        # X-CONTENT-TYPE-OPTIONS
        # --------------------------------------------------
        elif "x-content-type-options" in title:

            intelligence = {
                "why_it_matters": (
                    "X-Content-Type-Options helps prevent browsers from "
                    "incorrectly guessing or interpreting the MIME type "
                    "of downloaded resources."
                ),
                "possible_impact": (
                    "Without this protection, browser MIME-type sniffing "
                    "may create unintended content interpretation risks."
                ),
                "recommended_fix": (
                    "Configure the X-Content-Type-Options header with "
                    "the value 'nosniff'."
                )
            }

        # --------------------------------------------------
        # STRICT TRANSPORT SECURITY
        # --------------------------------------------------
        elif "strict-transport-security" in title:

            intelligence = {
                "why_it_matters": (
                    "Strict-Transport-Security instructs compatible "
                    "browsers to prefer secure HTTPS connections."
                ),
                "possible_impact": (
                    "Users may have reduced protection against accidental "
                    "or unintended use of insecure HTTP connections."
                ),
                "recommended_fix": (
                    "After confirming HTTPS is correctly configured, "
                    "enable Strict-Transport-Security with an appropriate "
                    "max-age value."
                )
            }

        # --------------------------------------------------
        # REFERRER POLICY
        # --------------------------------------------------
        elif "referrer-policy" in title:

            intelligence = {
                "why_it_matters": (
                    "Referrer-Policy controls how much referring URL "
                    "information a browser sends when navigating away "
                    "from a website."
                ),
                "possible_impact": (
                    "More URL information than necessary may potentially "
                    "be shared with external websites during navigation."
                ),
                "recommended_fix": (
                    "Configure a suitable Referrer-Policy such as "
                    "'strict-origin-when-cross-origin' based on the "
                    "application's requirements."
                )
            }

        # --------------------------------------------------
        # DANGEROUS HTTP METHODS
        # --------------------------------------------------
        elif "http trace" in title:

            intelligence = {
                "why_it_matters": (
                    "The TRACE method can return request information and "
                    "is often unnecessary for production applications."
                ),
                "possible_impact": (
                    "Unnecessary support for TRACE may increase the web "
                    "application's attack surface."
                ),
                "recommended_fix": (
                    "Disable the TRACE method unless there is a specific "
                    "operational requirement for it."
                )
            }

        elif "http put" in title:

            intelligence = {
                "why_it_matters": (
                    "The PUT method can allow clients to upload or modify "
                    "resources when the server is configured to permit it."
                ),
                "possible_impact": (
                    "Improper access controls could potentially allow "
                    "unauthorized modification or upload of resources."
                ),
                "recommended_fix": (
                    "Disable PUT if unnecessary and enforce strong "
                    "authentication and authorization where it is required."
                )
            }

        elif "http delete" in title:

            intelligence = {
                "why_it_matters": (
                    "The DELETE method can remove server-side resources "
                    "when supported by an application."
                ),
                "possible_impact": (
                    "Improper authorization could potentially allow "
                    "unauthorized deletion of resources."
                ),
                "recommended_fix": (
                    "Disable DELETE where unnecessary and enforce strict "
                    "authentication and authorization controls."
                )
            }

        elif "http connect" in title:

            intelligence = {
                "why_it_matters": (
                    "The CONNECT method can be used for proxy or tunneling "
                    "functionality."
                ),
                "possible_impact": (
                    "If unintentionally exposed, it may increase the risk "
                    "of misuse of proxy or tunneling functionality."
                ),
                "recommended_fix": (
                    "Disable CONNECT unless it is explicitly required and "
                    "restrict its use through appropriate access controls."
                )
            }

        # --------------------------------------------------
        # SENSITIVE FILE EXPOSURE
        # --------------------------------------------------
        elif ".env" in title:

            intelligence = {
                "why_it_matters": (
                    "Environment files may contain credentials, API keys, "
                    "database information, or other sensitive configuration."
                ),
                "possible_impact": (
                    "Exposure could reveal sensitive information that may "
                    "assist unauthorized access or further attacks."
                ),
                "recommended_fix": (
                    "Remove environment files from public directories and "
                    "explicitly block web access to sensitive files."
                )
            }

        elif "git repository" in title:

            intelligence = {
                "why_it_matters": (
                    "Publicly accessible Git files may expose source code "
                    "and historical project information."
                ),
                "possible_impact": (
                    "An attacker may obtain information about the "
                    "application that could assist further attacks."
                ),
                "recommended_fix": (
                    "Remove the .git directory from public web locations "
                    "and explicitly deny access at the web server level."
                )
            }

        elif "backup" in title:

            intelligence = {
                "why_it_matters": (
                    "Backup files may contain source code, databases, "
                    "configuration files, or other sensitive data."
                ),
                "possible_impact": (
                    "Exposure could reveal sensitive application or "
                    "system information."
                ),
                "recommended_fix": (
                    "Remove backup files from publicly accessible "
                    "directories and store them securely."
                )
            }

        # --------------------------------------------------
        # SSL / TLS
        # --------------------------------------------------
        elif (
            "ssl" in title
            or "tls" in title
            or "certificate" in title
        ):

            intelligence = {
                "why_it_matters": (
                    "SSL/TLS certificates help verify server identity and "
                    "protect encrypted communications."
                ),
                "possible_impact": (
                    "Users may receive security warnings and confidence "
                    "in the secure connection may be reduced."
                ),
                "recommended_fix": (
                    "Renew or correctly configure the certificate and "
                    "ensure the certificate chain is valid and trusted."
                )
            }

        # --------------------------------------------------
        # HIGH SEVERITY FALLBACK
        # --------------------------------------------------
        elif severity == "high":

            intelligence["possible_impact"] = (
                "This issue may present a significant security risk and "
                "should be reviewed as a priority."
            )

        # Add intelligence to the finding
        finding["why_it_matters"] = intelligence[
            "why_it_matters"
        ]

        finding["possible_impact"] = intelligence[
            "possible_impact"
        ]

        finding["recommended_fix"] = intelligence[
            "recommended_fix"
        ]

    return findings