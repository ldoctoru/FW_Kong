# autoupdate.rsc  -  automatic RouterOS + RouterBOARD firmware updates (RouterOS v7)
#
# Creates two schedulers (names use letters only, RouterOS is picky):
#   autoupdate  every day 04:00: check the channel; if a new version exists, save a backup
#               and an export, then install it (the router reboots by itself, ~2-3 min).
#   fwupgrade   at every boot (after 3 min): if the RouterBOARD firmware is older than the
#               one in the installed package, upgrade it and reboot once. No loop: it only
#               acts when the two versions differ.
# Everything is logged:  /log print where message~"autoupdate"
#
# Stop it:    /system scheduler disable autoupdate
# Channel:    change "stable" below to "long-term" for fewer, more conservative updates.
# Re-runnable: removes its own schedulers first.
#
# Notes: an update reboots the router, so port forwards, DNS and DDNS are down for a few
# minutes. A backup is written first: pre-update-<old version>.backup / .rsc (they hold
# secrets; keep them off Git, see .gitignore). Roll back a bad version by uploading the old
# package and rebooting, or restore the backup.

/system scheduler remove [find name=autoupdate]
/system scheduler remove [find name=fwupgrade]

/system scheduler add name=autoupdate start-time=04:00:00 interval=1d comment="fw: RouterOS auto update" on-event={
  /system package update set channel=stable
  /system package update check-for-updates once
  :delay 20s
  :local st [/system package update get status]
  :local cur [/system package update get installed-version]
  :local new [/system package update get latest-version]
  :if ($st~"New version") do={
    :log info ("autoupdate: update available " . $cur . " -> " . $new . ", saving backup then installing")
    /system backup save name=("pre-update-" . $cur)
    /export hide-sensitive file=("pre-update-" . $cur)
    :delay 10s
    /system package update install
  } else={
    :log info ("autoupdate: nothing to do (" . $st . ", running " . $cur . ")")
  }
}

/system scheduler add name=fwupgrade start-time=startup interval=0 comment="fw: RouterBOARD firmware upgrade after update" on-event={
  :delay 3m
  :local curfw [/system routerboard get current-firmware]
  :local newfw [/system routerboard get upgrade-firmware]
  :if ($curfw != $newfw) do={
    :log info ("autoupdate: RouterBOARD firmware " . $curfw . " -> " . $newfw . ", upgrading and rebooting")
    /system routerboard upgrade
    :delay 15s
    /system reboot
  } else={
    :log info ("autoupdate: RouterBOARD firmware up to date (" . $curfw . ")")
  }
}
