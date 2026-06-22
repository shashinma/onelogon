import logging
import time
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from impacket.smbconnection import SMBConnection, SessionError


class RegChecker:
    def __init__(self, conn: SMBConnection):
        self.logger = logging.getLogger("onelogon")
        self.conn = conn

    def crawl(self):
        self.trigger_winreg()
        try:
            remoteOps = RemoteOperations(self.conn, False)
            remoteOps.enableRegistry()

            regHandle = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)["phKey"]
            keyHandle = rrp.hBaseRegOpenKey(remoteOps._RemoteOperations__rrp, regHandle, "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters")["phkResult"]
            value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, keyHandle, "VulnerableChannelAllowList")[1].rstrip("\x00")
            self.logger.success(f"Found VulnerableChannelAllowList registry configuration: {value}")
        except Exception as e:
            self.logger.error(f"Error while querying registry: {e}")

    def trigger_winreg(self):
        # Original idea from https://twitter.com/splinter_code/status/1715876413474025704
        # Basically triggers the RemoteRegistry to start without admin privs
        tid = self.conn.connectTree("IPC$")
        try:
            self.conn.openFile(
                tid,
                r"\winreg",
                0x12019F,
                creationOption=0x40,
                fileAttributes=0x80,
            )
        except SessionError as e:
            # STATUS_PIPE_NOT_AVAILABLE error is expected
            self.logger.debug(str(e))
        # Give remote registry time to start
        time.sleep(1)
