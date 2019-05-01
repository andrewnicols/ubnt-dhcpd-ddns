#!/usr/bin/python
# -----------------------------------------------------------------
# route53-update.py -- Create or updates a DNS record in Amazon's Route 53.
#
# See documentation here:
# http://docs.amazonwebservices.com/Route53/2012-02-29/DeveloperGuide/RESTRequests.html
#
# Copyright 2012 Michael Kelly (michael@michaelkelly.org)
# Copyright 2019 Andrew Nicols <andrew@nicols.co.uk>
#
# This program is released under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# Mon Aug 20 03:42:03 EDT 2012
# Based on a scripy by Michael Kelly at https://github.com/mjkelly/experiments/tree/master/dns
# -----------------------------------------------------------------

from xml.etree import ElementTree
import base64
import hashlib
import hmac
import httplib
import optparse
import socket
import sys
import syslog
import ConfigParser

config = ConfigParser.SafeConfigParser({'aws_iam_key': None,
                                        'aws_iam_secret': None,
                                        'domain': None,
                                        'zoneid': None,
                                        'ttl': "300",
                                        'verbose': "no",
                                        'quiet': "no",
                                        'force': "no",
                                        'syslog': "yes"})
config.add_section('ddns')
config.read('config.ini')

parser = optparse.OptionParser()
parser.add_option('--hostname', dest='hostname',
                  help='Hostname to update within the specified domain.')
parser.add_option('--ip', dest='ip',
                  help='New IPv4 for host. Required')
parser.add_option('--ttl', dest='ttl',
                  default=config.getint('ddns', 'ttl'),
                  help='The TTL for the new entry.')
parser.add_option('--amz-key-id', dest='key_id',
                  default=config.get('ddns', 'aws_iam_key'),
                  help='Amazon API key ID. Required.')
parser.add_option('--amz-key-secret', dest='key_secret',
                  default=config.get('ddns', 'aws_iam_secret'),
                  help='Amazon API key secet value. Required.')
parser.add_option('--domain', dest='domain',
                  default=config.get('ddns', 'domain'),
                  help='The domain which the host is in. Must have a trailing . and be fully qualified.')
parser.add_option('--zoneid', dest='zoneid',
                  default=config.get('ddns', 'aws_r53_zoneid'),
                  help='Amazon zone ID containing domain name. Required.')
parser.add_option('--quiet', '-q', dest='quiet',
                  action="store_true",
                  default=config.getboolean('ddns', 'quiet'),
                  help="Don't output to stdout unless there is an error.")
parser.add_option('--verbose', '-v', dest='verbose',
                  action="store_true",
                  default=config.getboolean('ddns', 'verbose'),
                  help="Output more information.")
parser.add_option('--force', '-f', dest='force',
                  action="store_true",
                  default=config.getboolean('ddns', 'force'),
                  help="Update the A record even if it has not changed.")
parser.add_option('--syslog', '-s', dest='syslog',
                  action="store_true",
                  default=config.getboolean('ddns', 'syslog'),
                  help="Send output to syslog")
opts, _ = parser.parse_args()

AMAZON_NS = 'https://route53.amazonaws.com/doc/2012-02-29/'

COMMENT_FORMAT = 'Automatic update from route53-update.py running on {hostname} at {time}'

# Format string for updating an A record, {name}, from {old_value} with
# {old_ttl} to {new_value} with {new_ttl}.
# See:
# http://docs.amazonwebservices.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
CREATE_FORMAT = """<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2012-02-29/">
   <ChangeBatch>
      <Comment>{comment}</Comment>
      <Changes>
         <Change>
            <Action>CREATE</Action>
            <ResourceRecordSet>
               <Name>{name}</Name>
               <Type>A</Type>
               <TTL>{new_ttl}</TTL>
               <ResourceRecords>
                  <ResourceRecord>
                     <Value>{new_value}</Value>
                  </ResourceRecord>
               </ResourceRecords>
            </ResourceRecordSet>
         </Change>
      </Changes>
   </ChangeBatch>
</ChangeResourceRecordSetsRequest>
"""
UPDATE_FORMAT = """<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2012-02-29/">
   <ChangeBatch>
      <Comment>{comment}</Comment>
      <Changes>
         <Change>
            <Action>DELETE</Action>
            <ResourceRecordSet>
               <Name>{name}</Name>
               <Type>A</Type>
               <TTL>{old_ttl}</TTL>
               <ResourceRecords>
                  <ResourceRecord>
                     <Value>{old_value}</Value>
                  </ResourceRecord>
               </ResourceRecords>
            </ResourceRecordSet>
         </Change>
         <Change>
            <Action>CREATE</Action>
            <ResourceRecordSet>
               <Name>{name}</Name>
               <Type>A</Type>
               <TTL>{new_ttl}</TTL>
               <ResourceRecords>
                  <ResourceRecord>
                     <Value>{new_value}</Value>
                  </ResourceRecord>
               </ResourceRecords>
            </ResourceRecordSet>
         </Change>
      </Changes>
   </ChangeBatch>
</ChangeResourceRecordSetsRequest>
"""

def usage():
  parser.print_help()
  sys.exit(2)

def log(msg):
  """Print unless we're in quiet mode.

  If syslog is enabled, print to standard out only if it is tty.
  """
  if not opts.quiet:
    if opts.syslog:
      syslog.syslog(syslog.LOG_NOTICE, msg)
    if not opts.syslog or sys.stdout.isatty():
      print msg

def vlog(msg):
  """Print if we're in verbose mode."""
  if opts.verbose:
    log(msg)

def get_time_and_ip():
  """Gets the current time from amazon servers.

  Also saves the IP address of the socket it uses to make the request. These
  two bits of functionality are bundled because the IP comes for free from the
  socket we use to get the date, and we might need the IP later.

  Format is RFC 1123.
  http://docs.amazonwebservices.com/Route53/latest/DeveloperGuide/RESTAuthentication.html#StringToSign

  Returns:
    (date, ipaddr)
  """
  connection = httplib.HTTPSConnection('route53.amazonaws.com')
  connection.request('GET', '/date')
  response = connection.getresponse()
  ip = connection.sock.getsockname()[0]
  return response.getheader('Date'), ip

def make_auth(time_str, key_id, secret):
  """Creates an amazon authorization string.

  Format is specified here:
  http://docs.amazonwebservices.com/Route53/latest/DeveloperGuide/RESTAuthentication.html#AuthorizationHeader
  """
  h = hmac.new(secret, time_str, hashlib.sha256)
  h_b64 = base64.b64encode(h.digest())
  return 'AWS3-HTTPS AWSAccessKeyId=%s,Algorithm=HmacSHA256,Signature=%s' % (
      key_id, h_b64)

def qualify_path(path):
  return path.replace('/', '/{%s}' % AMAZON_NS)

def get_old_record_values(doc, name):
  """Returns the old values of the record we will update.

  Args:
    doc: the XML document of the existing record (just a single
        ResourceRecord), as a string.
    name: The name of the record (domain name) to update.

  Returns:
    (ip, TTL): the IP and TTL of the existing record
  """
  # TODO(mjkelly): This method could really use some tests.
  root = ElementTree.fromstring(doc)
  recordset_path = './ResourceRecordSets/ResourceRecordSet'
  value_path = './ResourceRecords/ResourceRecord/Value'

  # TODO(mjkelly): Consider just grabbing the content of <ResourceRecords>
  # verbatim so we can put it in the delete part of our request. ElementTree
  # doesn't print out the XML tree like it comes in, though -- I don't know if
  # Route 53 will understand it.
  for node in root.findall(qualify_path(recordset_path)):
    rec_name = node.find(qualify_path('./Name'))
    rec_type = node.find(qualify_path('./Type'))
    rec_ttl = node.find(qualify_path('./TTL'))
    rec_values = list(node.findall(qualify_path(value_path)))
    if rec_name is None or rec_type is None or rec_ttl is None:
      raise ValueError("Response does not have required children: Name, Type, TTL")

    rec_name, rec_type, rec_ttl = rec_name.text, rec_type.text, rec_ttl.text
    rec_value = rec_values[0].text
    if rec_name != name:
      vlog('Skipping record with name %s (searching for "%s")' % (
          rec_name, name))
      continue
    if rec_type != 'A':
      vlog('Skipping node with type %s (seaching for "A")' % rec_type)
      continue
    if len(rec_values) != 1:
      raise ValueError("Record must contain exactly Value element")

    vlog("Found suitable record: %s %s (TTL=%s) = %s" % (
        rec_type, rec_name, rec_ttl, rec_value))
    return rec_value, rec_ttl

  vlog('Could not find existing A record for %r in:\n%s' % (name, doc))
  return None, None

def find_comment_in_response(response, required_comment):
  """Checks for a PENDING or INSYNC ChangeResponse with the given comment.

  Args:
    response: XML ChangeResourceRecordSetsResponse, as a string.
    required_comment: Comment string to look for.

  Returns:
    The ElementTree.Element the ChangeInfo with required_comment, or None if
    not found.
  """
  root = ElementTree.fromstring(response)
  info_path = './ChangeInfo'
  for node in root.findall(qualify_path(info_path)):
    comment = node.find(qualify_path('./Comment'))
    status = node.find(qualify_path('./Status'))
    if comment.text != required_comment:
      continue
    if status.text  not in ('PENDING', 'INSYNC'):
      vlog('Found unexpected status = %r' % status.text)
      return None
    return node
  vlog('Found no response for comment %r' % required_comment)
  return None

# ========== main ==========

if opts.syslog:
  syslog.openlog('ubnt-dhcpd-ddns')

if (not opts.key_id or not opts.key_secret or not opts.domain or
    not opts.zoneid or not opts.ip):
  print >>sys.stderr, ('--amz-key-id, --amz-key-secret, --domain, --hostname, --zone-id, '
                       'and --ip are required.\n')
  usage()
if opts.quiet and opts.verbose:
  print >>sys.stderr, '--quiet and --verbose are mutually exclusive.'
  usage()

time_str, default_iface_ip = get_time_and_ip()
key_id = opts.key_id
secret = opts.key_secret
zoneid = opts.zoneid
domain = opts.domain.lower()
hostname = opts.hostname.lower()
new_ip = opts.ip
new_ttl = opts.ttl

if not hostname:
  log('Not setting a DNS record for %s. No hostname specified' % new_ip)
  sys.exit(1)

if hostname == "none":
  log('Not setting a DNS record for %s. No hostname specified' % new_ip)
  sys.exit(1)

if not domain.endswith('.'):
  print >>sys.stderr, '--domain should be fully-qualified, and end with a dot.'
  usage()

if hostname.endswith('.'):
  print >>sys.stderr, '--hostname should not be fully-qualified, and not end with a dot.'
  usage()

fqdn=("%s.%s" % (hostname, domain))

vlog('Will set %r to %r' % (fqdn, new_ip))

auth = make_auth(time_str, key_id, secret)
headers = {
  'X-Amz-Date': time_str,
  'X-Amzn-Authorization': auth,
}
# Path for GET request to list existing record only.
get_rrset_path = '/2012-02-29/hostedzone/%s/rrset?name=%s&type=A&maxitems=1' % (zoneid, fqdn)
# Path for POST request to update record.
change_rrset_path = '/2012-02-29/hostedzone/%s/rrset' % zoneid

connection = httplib.HTTPSConnection('route53.amazonaws.com')
vlog('GET %s' % get_rrset_path)

connection.request('GET', get_rrset_path, '', headers)
response = connection.getresponse()
response_txt = response.read()
vlog('Response:\n%s' % response_txt)

old_ip, old_ttl = get_old_record_values(response_txt, fqdn)

comment_str = COMMENT_FORMAT.format(hostname=socket.gethostname(),
                                    time=time_str)

if old_ip == new_ip and not opts.force:
  vlog('Old IP %s is same as new IP. Quitting.' % old_ip)
  sys.exit(0)
elif old_ip is None:
  log('Setting %s to %s' % (fqdn, new_ip))
  change_body = CREATE_FORMAT.format(comment=comment_str,
                                name=fqdn,
                                new_value=new_ip,
                                new_ttl=new_ttl)
else:
  log('Updating %s to %s (was %s)' % (fqdn, new_ip, old_ip))
  change_body = UPDATE_FORMAT.format(comment=comment_str,
                                    name=fqdn,
                                    old_value=old_ip,
                                    old_ttl=old_ttl,
                                    new_value=new_ip,
                                    new_ttl=new_ttl)
connection = httplib.HTTPSConnection('route53.amazonaws.com')
vlog('POST %s\n%s' % (change_rrset_path, change_body))

connection.request('POST', change_rrset_path, change_body, headers)
response = connection.getresponse()
response_val = response.read()
vlog('Response:\n%s' % response_val)

if response.status != httplib.OK:
  raise RuntimeError('Address update returned non-OK repsonse: %s (not %s)' % (
      response.status, httplib.OK))
if find_comment_in_response(response_val, comment_str) is None:
  raise RuntimeError(
    'Did not receive correct change response from Route 53. Response: %s',
    response_val)
