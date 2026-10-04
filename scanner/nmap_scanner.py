import nmap
import shutil


# =========================================================
# NMAP CONFIGURATION
# =========================================================

def find_nmap():

    # -----------------------------------------------------
    # Try to find Nmap automatically from system PATH
    # Works on Linux, macOS and Windows
    # -----------------------------------------------------

    nmap_executable = shutil.which("nmap")

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
        # Locate Nmap automatically
        # -------------------------------------------------

        nmap_path = find_nmap()


        # -------------------------------------------------
        # Initialize Nmap
        # -------------------------------------------------

        scanner = nmap.PortScanner(

            nmap_search_path=(
                nmap_path,
            )

        )


        # -------------------------------------------------
        # Build scan arguments
        #
        # -Pn tells Nmap to skip host discovery.
        # This is important for cloud deployments where
        # ICMP/host discovery may be blocked.
        # -------------------------------------------------

        if scan_profile == "all":

            arguments = (

                "-sV "

                "-Pn "

                "-p- "

                "--script vuln"

            )

        else:

            port_count = profile_ports[
                scan_profile
            ]

            arguments = (

                "-sV "

                "-Pn "

                f"--top-ports {port_count} "

                "--script vuln"

            )


        # -------------------------------------------------
        # Execute scan
        # -------------------------------------------------

        scanner.scan(

            hosts=target,

            arguments=arguments

        )


        results = []


        # =================================================
        # PROCESS DISCOVERED HOSTS
        # =================================================

        for host in scanner.all_hosts():


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