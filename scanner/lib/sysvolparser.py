import logging
import traceback
from impacket.smbconnection import SMBConnection, SessionError
from configparser import ConfigParser


class SysvolParser:
    def __init__(self, conn: SMBConnection):
        self.logger = logging.getLogger("onelogon")
        self.conn = conn
        self.domain = conn.getServerDNSDomainName()
        self.share = "SYSVOL"

    def _find_vulnchannellist(self):
        def output_callback(data):
            self.gpo_data += data

        found_dacls = []

        policies = self.conn.listPath("SYSVOL", f"{self.domain}/Policies/*")
        for policy in policies:
            # Skip "." and ".." directory pointers to avoid path errors
            if policy.get_longname() in [".", ".."]:
                continue

            try:
                self.gpo_data = b""
                self.conn.getFile("SYSVOL", f"{self.domain}/Policies/{policy.get_longname()}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf", output_callback)

                try:
                    decoded_data = self.gpo_data.decode("utf-8")
                except UnicodeDecodeError:
                    self.logger.debug(f"Failed to decode GPO data for policy {policy.get_shortname()} as UTF-8, trying UTF-16...")
                    decoded_data = self.gpo_data.decode("utf-16")

                # Use strict=False and interpolation=None to safely handle Windows INI quirks and % variables.
                # Some sections (e.g. [Service General Setting]) use value-less CSV-style rows like:
                # "WinRM",2,""
                # which require allow_no_value=True to avoid ParsingError.
                config_parser = ConfigParser(strict=False, interpolation=None, allow_no_value=True)
                config_parser.read_string(decoded_data)

                for section in config_parser.sections():
                    for key, value in config_parser.items(section):
                        if key == "MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\VulnerableChannelAllowList".lower():
                            self.logger.debug(f"Found vulnerable channel allow list: {value}")
                            try:
                                # Strip the surrounding double quotes from the extracted string
                                found_dacls.append({"name": policy.get_shortname(), "data": value[2:].strip('"')})
                            except Exception as e:
                                self.logger.error(f"Could not parse Registry Policy (error: {e}): {section} {key} {value}")
            except SessionError as e:
                # Catch and safely ignore expected "file not found" errors for policies without security settings
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e) or "STATUS_NO_SUCH_FILE" in str(e):
                    pass
                else:
                    self.logger.debug(f"SMB Session Error reading policy {policy.get_shortname()}: {e}")
            except Exception as e:
                self.logger.error(f"Error parsing policy {policy.get_shortname()}, {e.__class__.__name__}: {e}")
                if self.logger.level == logging.DEBUG:
                    traceback.print_exc()

        if found_dacls:
            self.logger.success(f"Found {len(found_dacls)} matching policies in SYSVOL Share.")
            for dacl in found_dacls:
                self.logger.success(f"Found vulnerable channel allow list in policy '{dacl['name']}': '{dacl['data']}'")
        else:
            self.logger.error("No matching policies found in SYSVOL Share.")

    def crawl(self) -> tuple[str, int]:
        try:
            self._find_vulnchannellist()
        except Exception as e:
            self.logger.error(f"Error while crawling SYSVOL Share: {e}")
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()
