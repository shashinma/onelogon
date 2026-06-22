import contextlib
import logging
import sys
import traceback
from impacket.smbconnection import SMBConnection


class SMB:
    def __init__(self):
        self.logger = logging.getLogger("onelogon")
        self.conn = None

    def _createSMBConnection(self, domain, username, password, dcIp, kerberos=False, dcName="", lmhash="", nthash="", aesKey=""):
        """Create a SMB connection to the target"""
        if not domain:
            with contextlib.suppress(Exception):
                conn = SMBConnection(remoteName=dcIp, remoteHost=dcIp, sess_port=445)
                conn.login("", "")
                domain = conn.getServerDNSDomainName()
                conn.logoff()
                conn.close()
        try:
            if kerberos:
                self.conn = SMBConnection(remoteName=dcName, remoteHost=dcIp, sess_port=445)
            else:
                self.conn = SMBConnection(remoteName=dcIp, remoteHost=dcIp, sess_port=445)

            if kerberos is True:
                self.conn.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, dcIp, useCache=False)
            else:
                self.conn.login(username, password, domain, lmhash, nthash)
            if self.conn.isGuestSession() > 0:
                self.logger.debug("GUEST Session Granted")
            else:
                self.logger.debug("USER Session Granted")
        except Exception as e:
            self.logger.error(f"Error: {e}")
            self.logger.debug(traceback.format_exc())
            self.logger.error("Failed to establish SMB connection. Exiting...")
            exit(1)

    def get_smb_connection(self, domain, username, password, dcIp, kerberos=False, dcName="", lmhash="", nthash="", aesKey=""):
        if not password and not lmhash and not nthash and not aesKey:
            self.logger.error("Error: At least one of Password, LM Hash, NT Hash or AES Key is required to connect to the SYSVOL Share. Exiting...")
            sys.exit(1)

        if not self.conn:
            self._createSMBConnection(domain, username, password, dcIp, kerberos, dcName, lmhash, nthash, aesKey)
        return self.conn
