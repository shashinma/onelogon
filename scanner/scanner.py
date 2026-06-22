import argparse
import contextlib
from pprint import pformat
from scanner.lib.regchecker import RegChecker
from scanner.lib.smb import SMB
from scanner.lib.sysvolparser import SysvolParser
from scanner.lib.logger import initLogger


def main():
    parser = argparse.ArgumentParser(description="onelogon configuration Scanner")
    parser.add_argument("-v", "--version", action="version", version="Current Version: %(prog)s 2.0")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-ts", "--timestamp", action="store_true", help="Add timestamp to log messages")

    auth = parser.add_argument_group("Authentication")
    auth.add_argument("--dc-ip", metavar="", required=True, dest="dcIp", help="IP Address of the domain controller")
    auth.add_argument("-u", "--username", metavar="", required=True, help="Username to authenticate with")
    auth.add_argument("-p", "--password", metavar="", help="Password to authenticate with")
    auth.add_argument("-d", "--domain", metavar="", help="Domain to authenticate with")
    auth.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication instead of NTLM")
    auth.add_argument("--dc-name", metavar="", dest="dcName", help="Domain Controller Name to authenticate with, required for Kerberos authentication", required=parser.parse_known_args()[0].kerberos)

    args = parser.parse_args()

    logger = initLogger(ts=args.timestamp, debug=args.debug)
    logger.debug("Passed args:\n" + pformat(vars(args)))

    smb = SMB()
    conn = smb.get_smb_connection(
        domain=args.domain,
        username=args.username,
        password=args.password,
        dcIp=args.dcIp,
        kerberos=args.kerberos,
        dcName=args.dcName
    )
    if not conn:
        logger.error("Failed to establish SMB connection. Exiting...")
        return
    scanner = SysvolParser(conn)
    scanner.crawl()
    regchecker = RegChecker(conn)
    regchecker.crawl()

    with contextlib.suppress(Exception):
        conn.logoff()
        conn.close()


if __name__ == "__main__":
    main()
