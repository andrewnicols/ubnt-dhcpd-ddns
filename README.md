# Ubiquiti DHCPD Dynamic DNS using AWS

This set of scripts adds support for forward and reverse DNS entries for your DHCP clients, making use of Amazon AWS Route-53 zones.

It supports both forward, and reverse zones.

## Installation

### Requirements

You will need an IAM user which grants the following actions to each of the relevant zones:

```
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets",
        "route53:ChangeResourceRecordSets"
```

### Assisted installation

```
    curl https://raw.githubusercontent.com/andrewnicols/ubnt-dhcpd-ddns/master/install.sh > /tmp/install.sh
    bash /tmp/install.sh
```

## Configuration

Configuration is located at `/config/scripts/ubnt-dhcpd-ddns/config.ini`.

You must specify your forwards zone, and IAM credentials.
You may optionally specify the reverse DNS zones.  Only /24 zones are currently supported.

```
[ddns]
domain          = per.nicols.uk.
syslog          = True
verbose         = False
aws_iam_key     = YOUR_KEY_HERE
aws_iam_secret  = YOUR_SECRET_HERE
reverse         = True

[per.nicols.uk.]
aws_r53_zoneid  = MY_ZONE_ID

[10.30.172.in-addr.arpa.]
aws_r53_zoneid  = MY_ZONE_ID

[11.30.172.in-addr.arpa.]
aws_r53_zoneid  = MY_ZONE_ID
```

### Reverse DNS configuration
Reverse DNS configuration is an optional extra, and requires one additional Route-53 zone per /24 network.

You will need to know the IP of a DNS server which is capable of resolving the request.

You will also need to configure the forward DNS for the reverse zones in your vyatta DNS configuration:

```
configure
set service dns options server=/10.30.172.in-addr.arpa/205.251.193.126
set service dns options server=/11.30.172.in-addr.arpa/205.251.193.181
commit
save
```

## Copyright and License

This set of scripts is copyright [Andrew Nicols](mailto:andrew@nicols.co.uk) and
based on an original script by Copyright 2012 Michael Kelly
(michael@michaelkelly.org)

The ubnt-dhcpd-ddns scripts are free software: you can redistribute it
and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

The ubnt-dhcpd-ddns scripts are distributed in the hope that it will
be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
Public License for more details.

You should have received a copy of the GNU General Public License
along with the plugin.  If not, see <http://www.gnu.org/licenses/>.
