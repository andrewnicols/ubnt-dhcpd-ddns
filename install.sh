#!/bin/bash
set -e

BRANCH=master
RAWBASE="https://raw.githubusercontent.com/andrewnicols/ubnt-dhcpd-ddns/${BRANCH}"
TARGETBASE=/config/scripts
CONFIGFILE="${TARGETBASE}/ubnt-dhcpd-ddns/config.ini"

echo "============================================================================"
echo "== Installing Dynamic DNS Updated for Ubiquiti DHCP"
echo "============================================================================"
echo

mkdir -p "${TARGETBASE}/ubnt-dhcpd-ddns" "${TARGETBASE}/post-config.d"

echo " == Fetching scripts"
echo "Fetching ${RAWBASE}/config/scripts/ubnt-dhcpd-ddns/route53-update.py"
curl -s -f "${RAWBASE}/config/scripts/ubnt-dhcpd-ddns/route53-update.py" > "${TARGETBASE}/ubnt-dhcpd-ddns/route53-update.py"

echo "Fetching ${RAWBASE}/config/scripts/post-config.d/ubnt-dhcpd-ddns.sh"
curl -s -f "${RAWBASE}/config/scripts/post-config.d/ubnt-dhcpd-ddns.sh" > "${TARGETBASE}/post-config.d/ubnt-dhcpd-ddns.sh"

chmod +x "${TARGETBASE}/ubnt-dhcpd-ddns/route53-update.py"
chmod +x "${TARGETBASE}/post-config.d/ubnt-dhcpd-ddns.sh"

if [ -f "${CONFIGFILE}" ]
then
  while true
  do
    read -p "Configuration already exists. Would you like to preserve it? Yn" yn
    case $yn in
      * )
        echo "Preserving existing configuration"
        break
        ;;
      [Yy]* )
        echo "Preserving existing configuration"
        break
        ;;
      [Nn]* )
        echo "Moving old configuration to ${CONFIGFILE}.old"
        mv "${CONFIGFILE}" "${CONFIGFILE}.old"
        break
        ;;
    esac
  done
fi

if [ ! -f "${CONFIGFILE}" ]
then
  echo "============================================================================"
  echo "== Setting up Dynamic DNS updates"
  echo "============================================================================"
  echo
  echo "----------------------------------------------------------------------------"
  echo "-- IAM Configuration"
  echo "----------------------------------------------------------------------------"
  read  -p "AWS IAM Key: " aws_iam_key
  read  -p "AWS IAM Secret: " aws_iam_secret
  echo
  echo "----------------------------------------------------------------------------"
  echo "-- Zone Configuration"
  echo "----------------------------------------------------------------------------"
  read -p "AWS R53 Zone ID: " aws_r53_zoneid
  read -p "FQDN domain including trailing . (e.g. perth.in.workplace.com.): " domain
  echo

  echo -n "Writing configuration to ${CONFIGFILE}... "
  cat << EOF > "${TARGETBASE}/ubnt-dhcpd-ddns/config.ini"
  [ddns]
  aws_iam_key=${aws_iam_key}
  aws_iam_secret=${aws_iam_secret}
  aws_r53_zoneid=${aws_r53_zoneid}
  domain=${domain}
EOF
  echo "done."
fi

while true
do
  read -p "Would you like to run the installer now? [yN]" yn
  case $yn in
    [Yy]* )
      echo "Installing now."
      # Note: This must run as route because it accesses the log file.
      # post-config.d scripts are normally run as root on boot.
      echo sudo "${TARGETBASE}/ubnt-dhcpd-ddns/post-config.d/ubnt-dhcpd-ddns.sh"
      break
      ;;
    [Nn]* )
      echo "Skipping configuration installation"
      break
      ;;
    * )
      echo "Skipping configuration installation"
      break
      ;;
  esac
done

echo "Complete."
exit 0
