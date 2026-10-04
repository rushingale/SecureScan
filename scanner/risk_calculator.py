def calculate_risk(analysis):

    findings = analysis.get(
        "findings",
        []
    )

    score = 0

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }

    # Track findings already counted so the same
    # vulnerability detected on multiple ports does
    # not unfairly inflate the score.
    counted_findings = set()

    # Store all potential CVE references separately.
    potential_cves = {}


    # =====================================================
    # ANALYZE FINDINGS
    # =====================================================

    for finding in findings:

        severity = (
            finding
            .get("severity", "")
            .lower()
        )

        title = finding.get(
            "title",
            ""
        )

        source = finding.get(
            "source",
            ""
        )

        verification_status = finding.get(
            "verification_status",
            ""
        )


        # =================================================
        # POTENTIAL VULNERS / CVE REFERENCES
        # =================================================

        if (
            source == "Nmap NSE - Vulners"
            or "Requires Verification" in verification_status
        ):

            for cve in finding.get(
                "cves",
                []
            ):

                cve_id = cve.get(
                    "cve"
                )

                cvss = cve.get(
                    "cvss",
                    0
                )

                if not cve_id:
                    continue

                # Keep only the highest score for each CVE
                if (
                    cve_id not in potential_cves
                    or cvss > potential_cves[cve_id]
                ):

                    potential_cves[cve_id] = cvss

            # Do NOT count this as a confirmed
            # Critical/High finding.
            continue


        # =================================================
        # DEDUPLICATE NORMAL FINDINGS
        # =================================================

        finding_key = (
            title.lower(),
            source.lower()
        )

        if finding_key in counted_findings:
            continue

        counted_findings.add(
            finding_key
        )


        if severity in severity_counts:

            severity_counts[
                severity
            ] += 1


    # =====================================================
    # CONFIRMED / DIRECT FINDING SCORE
    # =====================================================

    # Critical findings
    score += min(
        severity_counts["critical"] * 30,
        50
    )

    # High findings
    score += min(
        severity_counts["high"] * 15,
        30
    )

    # Medium findings
    score += min(
        severity_counts["medium"] * 6,
        24
    )

    # Low findings
    score += min(
        severity_counts["low"] * 2,
        8
    )

    # Info findings intentionally add zero.


    # =====================================================
    # POTENTIAL CVE REFERENCE SCORE
    # =====================================================

    if potential_cves:

        highest_cvss = max(
            potential_cves.values()
        )

        # CVEs identified only through software/version
        # matching receive reduced confidence weighting.

        if highest_cvss >= 9.0:

            score += 12

        elif highest_cvss >= 7.0:

            score += 8

        elif highest_cvss >= 4.0:

            score += 4

        else:

            score += 2


    # =====================================================
    # ATTACK SURFACE
    # =====================================================

    open_ports = (
        analysis
        .get("summary", {})
        .get("open_ports", 0)
    )


    if open_ports >= 10:

        score += 5

    elif open_ports >= 5:

        score += 3


    # =====================================================
    # FINAL SCORE
    # =====================================================

    score = min(
        round(score),
        100
    )


    # =====================================================
    # RISK LEVEL
    # =====================================================

    if score >= 85:

        level = "Critical"

    elif score >= 60:

        level = "High"

    elif score >= 30:

        level = "Medium"

    else:

        level = "Low"


    return {

        "score": score,

        "level": level,

        "severity_summary": severity_counts,

        "potential_cve_count": len(
            potential_cves
        )

    }