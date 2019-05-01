#!/bin/bash

readonly logFile="/tmp/provision_ddns.log"
source /opt/vyatta/etc/functions/script-template

configure > ${logFile}
set service dhcp-server global-parameters "on commit { set clientIp = binary-to-ascii(10, 8, &quot;.&quot; , leased-address); set clientHostname = pick-first-value(host-decl-name, option fqdn.hostname, option host-name, &quot;none&quot;); execute(&quot;/config/scripts/ubnt-dhcpd-ddns/route53-update.py&quot;, &quot;--ip&quot;, clientIp, &quot;--hostname&quot;, clientHostname); }" >> ${logFile}
commit >> ${logFile}
save >> ${logFile}
