import nmap
import shutil
import socket


# =========================================================
# NMAP CONFIGURATION
# =========================================================

def find_nmap():

    # -----------------------------------------------------
    # Try to find Nmap automatically from system PATH
    # -----------------------------------------------------

    nmap_executable = shutil.which("nmap")

    print(
        f"[NMAP DEBUG] shutil.which('nmap') = {nmap_executable}",
        flush=True
    )

    if nmap_executable:
        return nmap_executable


    # -----------------------------------------------------
    # Windows fallback paths
    # -----------------------------------------------------

    windows_paths = [

        r"C:\Program Files\Nmap\nmap.exe",

        r"C:\Program Files (x86)\Nmap\nmap.exe"

    ]


    for path in windows_paths:

        if shutil.which(path):

            print(
                f"[NMAP DEBUG] Found Nmap at: {path}",
                flush=True
            )

            return path


    # -----------------------------------------------------
    # Nmap was not found
    # -----------------------------------------------------

    raise FileNotFoundError(
        "Nmap was not found on this system. "
        "Please install Nmap and make sure it is available "
        "in the system PATH."
    )


# =========================================================
# SCAN TARGET
# =========================================================

def scan_target(target, scan_profile="top50"):

    profile_ports = {

        "top20": 20,

        "top50": 50,

        "top100": 100

    }


    # -----------------------------------------------------
    # Validate scan profile
    # -----------------------------------------------------

    if (
        scan_profile not in profile_ports
        and scan_profile != "all"
    ):

        scan_profile = "top50"


    try:

        # -------------------------------------------------
        # Diagnostic information
        # -------------------------------------------------

        print(
            "\n[NMAP DEBUG] ===============================",
            flush=True
        )

        print(
            f"[NMAP DEBUG] Target: {target}",
            flush=True
        )

        print(
            f"[NMAP DEBUG] Scan profile: {scan_profile}",
            flush=True
        )


        # -------------------------------------------------
        # Test DNS resolution
        # -------------------------------------------------

        try:

            resolved_addresses = socket.getaddrinfo(
                target,
                None
            )

            resolved_ips = sorted(
                set(
                    address[4][0]
                    for address in resolved_addresses
                )
            )

            print(
                f"[NMAP DEBUG] DNS resolved to: {resolved_ips}",
                flush=True
            )

        except Exception as dns_error:

            print(
                f"[NMAP DEBUG] DNS resolution FAILED: {dns_error}",
                flush=True
            )


        # -------------------------------------------------
        # Locate Nmap automatically
        # -------------------------------------------------

        nmap_path = find_nmap()

        print(
            f"[NMAP DEBUG] Nmap executable: {nmap_path}",
            flush=True
        )


        # -------------------------------------------------
        # Initialize Nmap
        # -------------------------------------------------

        scanner = nmap.PortScanner(

            nmap_search_path=(
                nmap_path,
            )

        )


        print(
            "[NMAP DEBUG] python-nmap initialized successfully",
            flush=True
        )


        # -------------------------------------------------
        # Build scan arguments
        #
        # -sT:
        # TCP Connect scan. Does not require raw sockets.
        #
        # -Pn:
        # Skip host discovery.
        #
        # --unprivileged:
        # Tell Nmap to operate without raw packet privileges.
        # -------------------------------------------------

        if scan_profile == "all":

            arguments = (

                "-sT "

                "-sV "

                "-Pn "

                "--unprivileged "

                "-p- "

                "--script vuln"

            )

        else:

            port_count = profile_ports[
                scan_profile
            ]

            arguments = (

                "-sT "

                "-sV "

                "-Pn "

                "--unprivileged "

                f"--top-ports {port_count} "

                "--script vuln"

            )


        print(
            f"[NMAP DEBUG] Arguments: {arguments}",
            flush=True
        )


        # -------------------------------------------------
        # Execute scan
        # -------------------------------------------------

        print(
            "[NMAP DEBUG] Starting Nmap scan...",
            flush=True
        )

        scanner.scan(

            hosts=target,

            arguments=arguments

        )


        # -------------------------------------------------
        # Get actual Nmap command
        # -------------------------------------------------

        try:

            print(
                f"[NMAP DEBUG] Command: "
                f"{scanner.command_line()}",
                flush=True
            )

        except Exception as command_error:

            print(
                f"[NMAP DEBUG] Could not read command line: "
                f"{command_error}",
                flush=True
            )


        # -------------------------------------------------
        # Get raw Nmap output if available
        # -------------------------------------------------

        try:

            last_output = scanner.get_nmap_last_output()

            if last_output:

                print(
                    "[NMAP DEBUG] Nmap last output:",
                    flush=True
                )

                print(
                    last_output,
                    flush=True
                )

        except Exception as output_error:

            print(
                f"[NMAP DEBUG] Could not read raw Nmap output: "
                f"{output_error}",
                flush=True
            )


        # -------------------------------------------------
        # Discovered hosts
        # -------------------------------------------------

        discovered_hosts = scanner.all_hosts()

        print(
            f"[NMAP DEBUG] Discovered hosts: "
            f"{discovered_hosts}",
            flush=True
        )

        print(
            f"[NMAP DEBUG] Host count: "
            f"{len(discovered_hosts)}",
            flush=True
        )


        results = []


        # =================================================
        # PROCESS DISCOVERED HOSTS
        # =================================================

        for host in discovered_hosts:

            print(
                f"[NMAP DEBUG] Processing host: {host}",
                flush=True
            )


            host_data = {

                "host":
                    host,

                "state":
                    scanner[host].state(),

                "protocols":
                    {},

                "vulnerabilities":
                    []

            }


            print(
                f"[NMAP DEBUG] Host state: "
                f"{host_data['state']}",
                flush=True
            )


            # =================================================
            # PROCESS PORTS
            # =================================================

            for protocol in scanner[
                host
            ].all_protocols():


                ports = []


                for port in scanner[
                    host
                ][protocol].keys():


                    port_info = scanner[
                        host
                    ][protocol][port]


                    print(
                        f"[NMAP DEBUG] Port: "
                        f"{port} | "
                        f"State: "
                        f"{port_info.get('state', '')} | "
                        f"Service: "
                        f"{port_info.get('name', '')}",
                        flush=True
                    )


                    ports.append({

                        "port":
                            port,

                        "state":
                            port_info.get(
                                "state",
                                ""
                            ),

                        "service":
                            port_info.get(
                                "name",
                                ""
                            ),

                        "product":
                            port_info.get(
                                "product",
                                ""
                            ),

                        "version":
                            port_info.get(
                                "version",
                                ""
                            )

                    })


                host_data[
                    "protocols"
                ][protocol] = ports


            # =================================================
            # HOST-LEVEL NSE SCRIPTS
            # =================================================

            host_scripts = scanner[
                host
            ].get(

                "script",

                {}

            )


            for script_name, output in host_scripts.items():

                print(
                    f"[NMAP DEBUG] Host NSE script: "
                    f"{script_name}",
                    flush=True
                )


                host_data[
                    "vulnerabilities"
                ].append({

                    "script":
                        script_name,

                    "output":
                        str(output),

                    "port":
                        None

                })


            # =================================================
            # PORT-LEVEL NSE SCRIPTS
            # =================================================

            for protocol in scanner[
                host
            ].all_protocols():


                for port in scanner[
                    host
                ][protocol].keys():


                    port_info = scanner[
                        host
                    ][protocol][port]


                    scripts = port_info.get(

                        "script",

                        {}

                    )


                    for script_name, output in scripts.items():

                        print(
                            f"[NMAP DEBUG] Port NSE script: "
                            f"{script_name} "
                            f"on port {port}",
                            flush=True
                        )


                        host_data[
                            "vulnerabilities"
                        ].append({

                            "script":
                                script_name,

                            "output":
                                str(output),

                            "port":
                                port

                        })


            results.append(
                host_data
            )


        # =================================================
        # FINAL DEBUG INFORMATION
        # =================================================

        print(
            f"[NMAP DEBUG] Final result count: "
            f"{len(results)}",
            flush=True
        )

        print(
            "[NMAP DEBUG] ===============================\n",
            flush=True
        )


        # =================================================
        # RETURN SCAN RESULT
        # =================================================

        return {

            "success":
                True,

            "target":
                target,

            "scan_profile":
                scan_profile,

            "nmap_arguments":
                arguments,

            "results":
                results

        }


    # =====================================================
    # ERROR HANDLING
    # =====================================================

    except Exception as e:

        print(
            "[NMAP ERROR] ===============================",
            flush=True
        )

        print(
            f"[NMAP ERROR] {type(e).__name__}: {e}",
            flush=True
        )

        print(
            "[NMAP ERROR] =================================",
            flush=True
        )


        return {

            "success":
                False,

            "target":
                target,

            "scan_profile":
                scan_profile,

            "error":
                str(e)

        }