# logging.rsc  -  keep login activity in its own log buffer (RouterOS v7)
# Failed and successful logins (WinBox, SSH, web, API) go to a separate buffer, so they
# are not pushed out by other log noise. Re-runnable.
#
#   See them:   /log print where buffer=auth-log
#   Failures:   /log print where buffer=auth-log and message~"failure"
#   Scanners:   /ip firewall address-list print where list=wan-mgmt-attempts
#               (internet hosts that tried to reach SSH, WinBox, web, telnet, FTP, API; kept 1 day)

/system logging remove [find action=auth-log]
/system logging action remove [find name=auth-log]
/system logging action add name=auth-log target=memory memory-lines=1000
/system logging add topics=account action=auth-log
/system logging add topics=system,error,critical action=auth-log
