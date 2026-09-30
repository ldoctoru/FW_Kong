# logging.rsc  -  keep login activity in its own log buffer (RouterOS v7)
# Failed and successful logins (WinBox, SSH, web, API) go to a separate buffer, so they
# are not pushed out by other log noise. Re-runnable.
#
#   See them:   /log print where buffer=authlog
#   Failures:   /log print where buffer=authlog and message~"failure"
#   Scanners:   /ip firewall address-list print where list=wan-mgmt-attempts
#               (internet hosts that tried to reach SSH, WinBox, web, telnet, FTP, API; kept 1 day)

/system logging remove [find action=authlog]
/system logging action remove [find name=authlog]
/system logging action add name=authlog target=memory memory-lines=1000
/system logging add topics=account action=authlog
/system logging add topics=system,error,critical action=authlog
