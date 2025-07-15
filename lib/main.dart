import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:fluttertoast/fluttertoast.dart';
import 'package:path_provider/path_provider.dart';
import 'package:dropdown_button2/dropdown_button2.dart';
import 'package:http/http.dart' as http;
import 'package:share_plus/share_plus.dart';

void main() {
  runApp(const NetworkanalyzerApp());
}

class NetworkanalyzerApp extends StatelessWidget {
  const NetworkanalyzerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: SplashScreen(),
      debugShowCheckedModeBanner: false,
    );
  }
}

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  @override
  void initState() {
    super.initState();
    Timer(Duration(seconds: 3), () {
      Navigator.pushReplacement(
          context, MaterialPageRoute(builder: (context) => Networkanalyzer()));
    });
  }

  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Image.asset('assets/network_analyzer.png', height: 150),
      ),
    );
  }
}

class Networkanalyzer extends StatefulWidget {
  const Networkanalyzer({super.key});

  @override
  State<StatefulWidget> createState() {
    return NetworkanalyzerState();
  }
}

class NetworkanalyzerState extends State<Networkanalyzer> {
  final TextEditingController commandController = TextEditingController();
  final TextEditingController targetController = TextEditingController();
  final TextEditingController serverController = TextEditingController();
  String? selectedTargetSpec;
  String? selectedHostDiscovery;
  String? selectedScanTech;
  String? selectedPortSpec;
  String? selectedServiceVersion;
  String? selectedOSDetection;
  String? selectedTimingPerformance;
  String? selectedFirewallIDS;
  String? selectedOutput;
  String? selectedMisc;
  String? selectedScript;
  String? selectedScriptlist;
  String serverAddress = '';
  bool isScanning = false;
  final List<String> targetSpecOptions = [
    '-iL',
    '-iR',
    '--exclude',
    '--excludefile'
  ];
  final List<String> hostDiscoveryOptions = [
    '-sL',
    '-sn',
    '-Pn',
    '-PS',
    '-PA',
    '-PU',
    '-PY',
    '-PE',
    '-PP',
    '-PM',
    '-PO',
    '-n',
    '-R',
    '--dns-servers',
    '--system-dns',
    '--traceroute'
  ];
  final List<String> scanTechOptions = [
    '-sS',
    '-sT',
    '-sA',
    '-sW',
    '-sM',
    '-sU',
    '-sN',
    '-sF',
    '-sX',
    '--scanflags',
    '-sI',
    '-sY',
    '-sZ',
    '-sO',
    '-b'
  ];
  final List<String> portSpecOptions = [
    '-p',
    '--exclude-ports',
    '-F',
    '-r',
    '--top-ports',
    '--port-ratio',
    '--open'
  ];
  final List<String> serviceVersionOptions = [
    '-sV',
    '--version-intensity',
    '--version-light',
    '--version-all',
    '--version-trace'
  ];
  final List<String> osDetectionOptions = [
    '-O',
    '--osscan-limit',
    '--osscan-guess'
  ];
  final List<String> timingPerformanceOptions = [
    'T0',
    '-T1',
    '-T2',
    '-T3',
    '-T4',
    '-T5',
    '--min-hostgroup',
    '--max-hostgroup',
    '--min-parallelism',
    '--max-parallelism',
    '--min-rtt-timeout',
    '--max-rtt-timeout',
    '--initial-rtt-timeout',
    '--max-retries',
    '--host-timeout',
    '--scan-delay',
    '--max-scan-delay',
    '--min-rate',
    '--max-rate'
  ];
  final List<String> firewallIDSOptions = [
    '-f',
    '--mtu',
    '-D',
    '-S',
    '-e',
    '-g',
    '--source-port',
    '--proxies',
    '--data',
    '--data-string',
    '--data-length',
    '--ip-options',
    '--ttl',
    '--spoof-mac',
    '--badsum'
  ];
  final List<String> outputOptions = ['-oN', '-oX', '-oG'];
  final List<String> miscOptions = [
    '-6',
    '-A',
    '--datadir',
    '--send-eth',
    '--send-ip',
    '--privileged',
    '--unprivileged',
    '-V',
    '-h'
  ];
  final List<String> scriptOptions = [
    '-sC',
    '--script',
    '--script-args',
    '--script-args-file',
    '--script-trace',
    '--script-updatedb',
    '--script-help'
  ];
  final List<String> scriptlistOptions = [
    'acarsd-info.nse',
    'address-info.nse',
    'afp-brute.nse',
    'afp-ls.nse',
    'afp-path-vuln.nse',
    'afp-serverinfo.nse',
    'afp-showmount.nse',
    'ajp-auth.nse',
    'ajp-brute.nse',
    'ajp-headers.nse',
    'ajp-methods.nse',
    'ajp-request.nse',
    'allseeingeye-info.nse',
    'amqp-info.nse',
    'asn-query.nse',
    'auth-owners.nse',
    'auth-spoof.nse',
    'backorifice-brute.nse',
    'backorifice-info.nse',
    'bacnet-info.nse',
    'banner.nse',
    'bitcoin-getaddr.nse',
    'bitcoin-info.nse',
    'bitcoinrpc-info.nse',
    'bittorrent-discovery.nse',
    'bjnp-discover.nse',
    'broadcast-ataoe-discover.nse',
    'broadcast-avahi-dos.nse',
    'broadcast-bjnp-discover.nse',
    'broadcast-db2-discover.nse',
    'broadcast-dhcp-discover.nse',
    'broadcast-dhcp6-discover.nse',
    'broadcast-dns-service-discovery.nse',
    'broadcast-dropbox-listener.nse',
    'broadcast-eigrp-discovery.nse',
    'broadcast-hid-discoveryd.nse',
    'broadcast-igmp-discovery.nse',
    'broadcast-jenkins-discover.nse',
    'broadcast-listener.nse',
    'broadcast-ms-sql-discover.nse',
    'broadcast-netbios-master-browser.nse',
    'broadcast-networker-discover.nse',
    'broadcast-novell-locate.nse',
    'broadcast-ospf2-discover.nse',
    'broadcast-pc-anywhere.nse',
    'broadcast-pc-duo.nse',
    'broadcast-pim-discovery.nse',
    'broadcast-ping.nse',
    'broadcast-pppoe-discover.nse',
    'broadcast-rip-discover.nse',
    'broadcast-ripng-discover.nse',
    'broadcast-sonicwall-discover.nse',
    'broadcast-sybase-asa-discover.nse',
    'broadcast-tellstick-discover.nse',
    'broadcast-upnp-info.nse',
    'broadcast-versant-locate.nse',
    'broadcast-wake-on-lan.nse',
    'broadcast-wpad-discover.nse',
    'broadcast-wsdd-discover.nse',
    'broadcast-xdmcp-discover.nse',
    'cassandra-brute.nse',
    'cassandra-info.nse',
    'cccam-version.nse',
    'cics-enum.nse',
    'cics-info.nse',
    'cics-user-brute.nse',
    'cics-user-enum.nse',
    'citrix-brute-xml.nse',
    'citrix-enum-apps-xml.nse',
    'citrix-enum-apps.nse',
    'citrix-enum-servers-xml.nse',
    'citrix-enum-servers.nse',
    'clamav-exec.nse',
    'clock-skew.nse',
    'coap-resources.nse',
    'couchdb-databases.nse',
    'couchdb-stats.nse',
    'creds-summary.nse',
    'cups-info.nse',
    'cups-queue-info.nse',
    'cvs-brute-repository.nse',
    'cvs-brute.nse',
    'daap-get-library.nse',
    'daytime.nse',
    'db2-das-info.nse',
    'deluge-rpc-brute.nse',
    'dhcp-discover.nse',
    'dicom-brute.nse',
    'dicom-ping.nse',
    'dict-info.nse',
    'distcc-cve2004-2687.nse',
    'dns-blacklist.nse',
    'dns-brute.nse',
    'dns-cache-snoop.nse',
    'dns-check-zone.nse',
    'dns-client-subnet-scan.nse',
    'dns-fuzz.nse',
    'dns-ip6-arpa-scan.nse',
    'dns-nsec-enum.nse',
    'dns-nsec3-enum.nse',
    'dns-nsid.nse',
    'dns-random-srcport.nse',
    'dns-random-txid.nse',
    'dns-recursion.nse',
    'dns-service-discovery.nse',
    'dns-srv-enum.nse',
    'dns-update.nse',
    'dns-zeustracker.nse',
    'dns-zone-transfer.nse',
    'docker-version.nse',
    'domcon-brute.nse',
    'domcon-cmd.nse',
    'domino-enum-users.nse',
    'dpap-brute.nse',
    'drda-brute.nse',
    'drda-info.nse',
    'duplicates.nse',
    'eap-info.nse',
    'enip-info.nse',
    'epmd-info.nse',
    'eppc-enum-processes.nse',
    'fcrdns.nse',
    'finger.nse',
    'fingerprint-strings.nse',
    'firewalk.nse',
    'firewall-bypass.nse',
    'flume-master-info.nse',
    'fox-info.nse',
    'freelancer-info.nse',
    'ftp-anon.nse',
    'ftp-bounce.nse',
    'ftp-brute.nse',
    'ftp-libopie.nse',
    'ftp-proftpd-backdoor.nse',
    'ftp-syst.nse',
    'ftp-vsftpd-backdoor.nse',
    'ftp-vuln-cve2010-4221.nse',
    'ganglia-info.nse',
    'giop-info.nse',
    'gkrellm-info.nse',
    'gopher-ls.nse',
    'gpsd-info.nse',
    'hadoop-datanode-info.nse',
    'hadoop-jobtracker-info.nse',
    'hadoop-namenode-info.nse',
    'hadoop-secondary-namenode-info.nse',
    'hadoop-tasktracker-info.nse',
    'hartip-info.nse',
    'hbase-master-info.nse',
    'hbase-region-info.nse',
    'hddtemp-info.nse',
    'hnap-info.nse',
    'hostmap-bfk.nse',
    'hostmap-crtsh.nse',
    'hostmap-robtex.nse',
    'http-adobe-coldfusion-apsa1301.nse',
    'http-affiliate-id.nse',
    'http-apache-negotiation.nse',
    'http-apache-server-status.nse',
    'http-aspnet-debug.nse',
    'http-auth-finder.nse',
    'http-auth.nse',
    'http-avaya-ipoffice-users.nse',
    'http-awstatstotals-exec.nse',
    'http-axis2-dir-traversal.nse',
    'http-backup-finder.nse',
    'http-barracuda-dir-traversal.nse',
    'http-bigip-cookie.nse',
    'http-brute.nse',
    'http-cakephp-version.nse',
    'http-chrono.nse',
    'http-cisco-anyconnect.nse',
    'http-coldfusion-subzero.nse',
    'http-comments-displayer.nse',
    'http-config-backup.nse',
    'http-cookie-flags.nse',
    'http-cors.nse',
    'http-cross-domain-policy.nse',
    'http-csrf.nse',
    'http-date.nse',
    'http-default-accounts.nse',
    'http-devframework.nse',
    'http-dlink-backdoor.nse',
    'http-dombased-xss.nse',
    'http-domino-enum-passwords.nse',
    'http-drupal-enum-users.nse',
    'http-drupal-enum.nse',
    'http-enum.nse',
    'http-errors.nse',
    'http-exif-spider.nse',
    'http-favicon.nse',
    'http-feed.nse',
    'http-fetch.nse',
    'http-fileupload-exploiter.nse',
    'http-form-brute.nse',
    'http-form-fuzzer.nse',
    'http-frontpage-login.nse',
    'http-generator.nse',
    'http-git.nse',
    'http-gitweb-projects-enum.nse',
    'http-google-malware.nse',
    'http-grep.nse',
    'http-headers.nse',
    'http-hp-ilo-info.nse',
    'http-huawei-hg5xx-vuln.nse',
    'http-icloud-findmyiphone.nse',
    'http-icloud-sendmsg.nse',
    'http-iis-short-name-brute.nse',
    'http-iis-webdav-vuln.nse',
    'http-internal-ip-disclosure.nse',
    'http-joomla-brute.nse',
    'http-jsonp-detection.nse',
    'http-litespeed-sourcecode-download.nse',
    'http-ls.nse',
    'http-majordomo2-dir-traversal.nse',
    'http-malware-host.nse',
    'http-mcmp.nse',
    'http-method-tamper.nse',
    'http-methods.nse',
    'http-mobileversion-checker.nse',
    'http-ntlm-info.nse',
    'http-open-proxy.nse',
    'http-open-redirect.nse',
    'http-passwd.nse',
    'http-php-version.nse',
    'http-phpmyadmin-dir-traversal.nse',
    'http-phpself-xss.nse',
    'http-proxy-brute.nse',
    'http-put.nse',
    'http-qnap-nas-info.nse',
    'http-referer-checker.nse',
    'http-rfi-spider.nse',
    'http-robots.txt.nse',
    'http-robtex-reverse-ip.nse',
    'http-robtex-shared-ns.nse',
    'http-sap-netweaver-leak.nse',
    'http-security-headers.nse',
    'http-server-header.nse',
    'http-shellshock.nse',
    'http-sitemap-generator.nse',
    'http-slowloris-check.nse',
    'http-slowloris.nse',
    'http-sql-injection.nse',
    'http-stored-xss.nse',
    'http-svn-enum.nse',
    'http-svn-info.nse',
    'http-title.nse',
    'http-tplink-dir-traversal.nse',
    'http-trace.nse',
    'http-traceroute.nse',
    'http-trane-info.nse',
    'http-unsafe-output-escaping.nse',
    'http-useragent-tester.nse',
    'http-userdir-enum.nse',
    'http-vhosts.nse',
    'http-virustotal.nse',
    'http-vlcstreamer-ls.nse',
    'http-vmware-path-vuln.nse',
    'http-vuln-cve2006-3392.nse',
    'http-vuln-cve2009-3960.nse',
    'http-vuln-cve2010-0738.nse',
    'http-vuln-cve2010-2861.nse',
    'http-vuln-cve2011-3192.nse',
    'http-vuln-cve2011-3368.nse',
    'http-vuln-cve2012-1823.nse',
    'http-vuln-cve2013-0156.nse',
    'http-vuln-cve2013-6786.nse',
    'http-vuln-cve2013-7091.nse',
    'http-vuln-cve2014-2126.nse',
    'http-vuln-cve2014-2127.nse',
    'http-vuln-cve2014-2128.nse',
    'http-vuln-cve2014-2129.nse',
    'http-vuln-cve2014-3704.nse',
    'http-vuln-cve2014-8877.nse',
    'http-vuln-cve2015-1427.nse',
    'http-vuln-cve2015-1635.nse',
    'http-vuln-cve2017-1001000.nse',
    'http-vuln-cve2017-5638.nse',
    'http-vuln-cve2017-5689.nse',
    'http-vuln-cve2017-8917.nse',
    'http-vuln-misfortune-cookie.nse',
    'http-vuln-wnr1000-creds.nse',
    'http-waf-detect.nse',
    'http-waf-fingerprint.nse',
    'http-webdav-scan.nse',
    'http-wordpress-brute.nse',
    'http-wordpress-enum.nse',
    'http-wordpress-users.nse',
    'http-xssed.nse',
    'https-redirect.nse',
    'iax2-brute.nse',
    'iax2-version.nse',
    'icap-info.nse',
    'iec-identify.nse',
    'iec61850-mms.nse',
    'ike-version.nse',
    'imap-brute.nse',
    'imap-capabilities.nse',
    'imap-ntlm-info.nse',
    'impress-remote-discover.nse',
    'informix-brute.nse',
    'informix-query.nse',
    'informix-tables.nse',
    'ip-forwarding.nse',
    'ip-geolocation-geoplugin.nse',
    'ip-geolocation-ipinfodb.nse',
    'ip-geolocation-map-bing.nse',
    'ip-geolocation-map-google.nse',
    'ip-geolocation-map-kml.nse',
    'ip-geolocation-maxmind.nse',
    'ip-https-discover.nse',
    'ipidseq.nse',
    'ipmi-brute.nse',
    'ipmi-cipher-zero.nse',
    'ipmi-version.nse',
    'ipv6-multicast-mld-list.nse',
    'ipv6-node-info.nse',
    'ipv6-ra-flood.nse',
    'irc-botnet-channels.nse',
    'irc-brute.nse',
    'irc-info.nse',
    'irc-sasl-brute.nse',
    'irc-unrealircd-backdoor.nse',
    'iscsi-brute.nse',
    'iscsi-info.nse',
    'isns-info.nse',
    'jdwp-exec.nse',
    'jdwp-info.nse',
    'jdwp-inject.nse',
    'jdwp-version.nse',
    'knx-gateway-discover.nse',
    'knx-gateway-info.nse',
    'krb5-enum-users.nse',
    'ldap-brute.nse',
    'ldap-novell-getpass.nse',
    'ldap-rootdse.nse',
    'ldap-search.nse',
    'lexmark-config.nse',
    'llmnr-resolve.nse',
    'lltd-discovery.nse',
    'lu-enum.nse',
    'maxdb-info.nse',
    'mcafee-epo-agent.nse',
    'membase-brute.nse',
    'membase-http-info.nse',
    'memcached-info.nse',
    'metasploit-info.nse',
    'metasploit-msgrpc-brute.nse',
    'metasploit-xmlrpc-brute.nse',
    'mikrotik-routeros-brute.nse',
    'mmouse-brute.nse',
    'mmouse-exec.nse',
    'modbus-discover.nse',
    'mongodb-brute.nse',
    'mongodb-databases.nse',
    'mongodb-info.nse',
    'mqtt-subscribe.nse',
    'mrinfo.nse',
    'ms-sql-brute.nse',
    'ms-sql-config.nse',
    'ms-sql-dac.nse',
    'ms-sql-dump-hashes.nse',
    'ms-sql-empty-password.nse',
    'ms-sql-hasdbaccess.nse',
    'ms-sql-info.nse',
    'ms-sql-ntlm-info.nse',
    'ms-sql-query.nse',
    'ms-sql-tables.nse',
    'ms-sql-xp-cmdshell.nse',
    'msrpc-enum.nse',
    'mtrace.nse',
    'multicast-profinet-discovery.nse',
    'murmur-version.nse',
    'mysql-audit.nse',
    'mysql-brute.nse',
    'mysql-databases.nse',
    'mysql-dump-hashes.nse',
    'mysql-empty-password.nse',
    'mysql-enum.nse',
    'mysql-info.nse',
    'mysql-query.nse',
    'mysql-users.nse',
    'mysql-variables.nse',
    'mysql-vuln-cve2012-2122.nse',
    'nat-pmp-info.nse',
    'nat-pmp-mapport.nse',
    'nbd-info.nse',
    'nbns-interfaces.nse',
    'nbstat.nse',
    'ncp-enum-users.nse',
    'ncp-serverinfo.nse',
    'ndmp-fs-info.nse',
    'ndmp-version.nse',
    'nessus-brute.nse',
    'nessus-xmlrpc-brute.nse',
    'netbus-auth-bypass.nse',
    'netbus-brute.nse',
    'netbus-info.nse',
    'netbus-version.nse',
    'nexpose-brute.nse',
    'nfs-ls.nse',
    'nfs-showmount.nse',
    'nfs-statfs.nse',
    'nje-node-brute.nse',
    'nje-pass-brute.nse',
    'nntp-ntlm-info.nse',
    'nping-brute.nse',
    'nrpe-enum.nse',
    'nse.txt',
    'nsescript.txt',
    'ntp-info.nse',
    'ntp-monlist.nse',
    'omp2-brute.nse',
    'omp2-enum-targets.nse',
    'omron-info.nse',
    'openflow-info.nse',
    'openlookup-info.nse',
    'openvas-otp-brute.nse',
    'openwebnet-discovery.nse',
    'oracle-brute-stealth',
    'oracle-brute.nse',
    'oracle-enum-users.nse',
    'oracle-sid-brute.nse',
    'oracle-tns-version.nse',
    'ovs-agent-version.nse',
    'p2p-conficker.nse',
    'path-mtu.nse',
    'pcanywhere-brute.nse',
    'pcworx-info.nse',
    'pgsql-brute.nse',
    'pjl-ready-message.nse',
    'pop3-brute.nse',
    'pop3-capabilities.nse',
    'pop3-ntlm-info.nse',
    'port-states.nse',
    'pptp-version.nse',
    'profinet-cm-lookup.nse',
    'puppet-naivesigning.nse',
    'qconn-exec.nse',
    'qscan.nse',
    'quake1-info.nse',
    'quake3-info.nse',
    'quake3-master-getservers.nse',
    'rdp-enum-encryption.nse',
    'rdp-ntlm-info.nse',
    'rdp-vuln-ms12-020.nse',
    'realvnc-auth-bypass.nse',
    'redis-brute.nse',
    'redis-info.nse',
    'resolveall.nse',
    'reverse-index.nse',
    'rexec-brute.nse',
    'rfc868-time.nse',
    'riak-http-info.nse',
    'rlogin-brute.nse',
    'rmi-dumpregistry.nse',
    'rmi-vuln-classloader.nse',
    'rpc-grind.nse',
    'rpcap-brute.nse',
    'rpcap-info.nse',
    'rpcinfo.nse',
    'rsa-vuln-roca.nse',
    'rsync-brute.nse',
    'rsync-list-modules.nse',
    'rtsp-methods.nse',
    'rtsp-url-brute.nse',
    'rusers.nse',
    's7-info.nse',
    'samba-vuln-cve-2012-1182.nse',
    'script.db',
    'servicetags.nse',
    'shodan-api.nse',
    'sip-brute.nse',
    'sip-call-spoof.nse',
    'sip-enum-users.nse',
    'sip-methods.nse',
    'skypev2-version.nse',
    'smb-brute.nse',
    'smb-double-pulsar-backdoor.nse',
    'smb-enum-domains.nse',
    'smb-enum-groups.nse',
    'smb-enum-processes.nse',
    'smb-enum-services.nse',
    'smb-enum-sessions.nse',
    'smb-enum-shares.nse',
    'smb-enum-users.nse',
    'smb-flood.nse',
    'smb-ls.nse',
    'smb-mbenum.nse',
    'smb-os-discovery.nse',
    'smb-print-text.nse',
    'smb-protocols.nse',
    'smb-psexec.nse',
    'smb-security-mode.nse',
    'smb-server-stats.nse',
    'smb-system-info.nse',
    'smb-vuln-conficker.nse',
    'smb-vuln-cve-2017-7494.nse',
    'smb-vuln-cve2009-3103.nse',
    'smb-vuln-ms06-025.nse',
    'smb-vuln-ms07-029.nse',
    'smb-vuln-ms08-067.nse',
    'smb-vuln-ms10-054.nse',
    'smb-vuln-ms10-061.nse',
    'smb-vuln-ms17-010.nse',
    'smb-vuln-regsvc-dos.nse',
    'smb-vuln-webexec.nse',
    'smb-webexec-exploit.nse',
    'smb2-capabilities.nse',
    'smb2-security-mode.nse',
    'smb2-time.nse',
    'smb2-vuln-uptime.nse',
    'smtp-brute.nse',
    'smtp-commands.nse',
    'smtp-enum-users.nse',
    'smtp-ntlm-info.nse',
    'smtp-open-relay.nse',
    'smtp-strangeport.nse',
    'smtp-vuln-cve2010-4344.nse',
    'smtp-vuln-cve2011-1720.nse',
    'smtp-vuln-cve2011-1764.nse',
    'sniffer-detect.nse',
    'snmp-brute.nse',
    'snmp-hh3c-logins.nse',
    'snmp-info.nse',
    'snmp-interfaces.nse',
    'snmp-ios-config.nse',
    'snmp-netstat.nse',
    'snmp-processes.nse',
    'snmp-sysdescr.nse',
    'snmp-win32-services.nse',
    'snmp-win32-shares.nse',
    'snmp-win32-software.nse',
    'snmp-win32-users.nse',
    'socks-auth-info.nse',
    'socks-brute.nse',
    'socks-open-proxy.nse',
    'ssh-auth-methods.nse',
    'ssh-brute.nse',
    'ssh-hostkey.nse',
    'ssh-publickey-acceptance.nse',
    'ssh-run.nse',
    'ssh2-enum-algos.nse',
    'sshv1.nse',
    'ssl-ccs-injection.nse',
    'ssl-cert-intaddr.nse',
    'ssl-cert.nse',
    'ssl-date.nse',
    'ssl-dh-params.nse',
    'ssl-enum-ciphers.nse',
    'ssl-heartbleed.nse',
    'ssl-known-key.nse',
    'ssl-poodle.nse',
    'sslv2-drown.nse',
    'sslv2.nse',
    'sstp-discover',
    'sslv2.nse',
    'stun-info.nse',
    'stun-version.nse',
    'stuxnet-detect.nse',
    'supermicro-ipmi-conf.nse',
    'svn-brute.nse',
    'targets-asn.nse',
    'targets-ipv6-map4to6.nse',
    'targets-ipv6-multicast-echo.nse',
    'targets-ipv6-multicast-invalid-dst.nse',
    'targets-ipv6-multicast-mld.nse',
    'targets-ipv6-multicast-slaac.nse',
    'targets-ipv6-wordlist.nse',
    'targets-sniffer.nse',
    'targets-traceroute.nse',
    'targets-xml.nse',
    'teamspeak2-version.nse',
    'telnet-brute.nse',
    'telnet-encryption.nse',
    'teamspeak2-version.nse',
    'telnet-brute.nse',
    'telnet-encryption.nse',
    'teamspeak2-version.nse',
    'telnet-brute.nse',
    'telnet-encryption.nse',
    'telnet-ntlm-info.nse',
    'tftp-enum.nse',
    'tftp-version.nse',
    'tls-alpn.nse',
    'tls-nextprotoneg.nse',
    'tls-ticketbleed.nse',
    'tn3270-screen.nse',
    'tor-consensus-checker.nse',
    'traceroute-geolocation.nse',
    'tso-brute.nse',
    'tso-enum.nse',
    'ubiquiti-discovery.nse',
    'unittest.nse',
    'unusual-port.nse',
    'upnp-info.nse',
    'uptime-agent-info.nse',
    'url-snarf.nse',
    'ventrilo-info.nse',
    'versant-info.nse',
    'vmauthd-brute.nse',
    'vmware-version.nse',
    'vnc-brute.nse',
    'vnc-info.nse',
    'vnc-title.nse',
    'voldemort-info.nse',
    'vtam-enum.nse',
    'vulners.nse',
    'vuze-dht-info.nse',
    'wdb-version.nse',
    'weblogic-t3-info.nse',
    'whois-domain.nse',
    'whois-ip.nse',
    'wsdd-discover.nse',
    'x11-access.nse',
    'xdmcp-discover.nse',
    'xmlrpc-methods.nse',
    'xmpp-brute.nse',
    'xmpp-info.nse',
  ];

  void updateCommand() {
    String command = 'sudo nmap';
    if (selectedTargetSpec != null) command += ' $selectedTargetSpec';
    if (selectedHostDiscovery != null) command += ' $selectedHostDiscovery';
    if (selectedScanTech != null) command += ' $selectedScanTech';
    if (selectedPortSpec != null) command += ' $selectedPortSpec';
    if (selectedServiceVersion != null) command += ' $selectedServiceVersion';
    if (selectedOSDetection != null) command += ' $selectedOSDetection';
    if (selectedTimingPerformance != null) {
      command += ' $selectedTimingPerformance';
    }
    if (selectedFirewallIDS != null) command += ' $selectedFirewallIDS';
    if (selectedOutput != null) command += ' $selectedOutput';
    if (selectedMisc != null) command += '$selectedMisc';
    if (selectedScript != null) command += ' $selectedScript';
    if (selectedScriptlist != null) command += '$selectedScriptlist';
    commandController.text = command;
  }

  Future<String> sendCommandtoServer(String command) async {
    final url = Uri.parse(serverAddress);
    final request = await http.post(url, body: {
      'command': command,
    });
    if (request.statusCode == 200) {
      return request.body;
    } else {
      showToast("Error:${request.statusCode}");
      throw Exception("Failed to execute Nmap Scan");
    }
  }

  Future<void> startScan() async {
    String command = commandController.text;
    String target = targetController.text;
    if (target.isEmpty) {
      showToast("Please enter a target.");
      return;
    }
    command += ' $target';
    commandController.text = command;
    setState(() {
      isScanning = true;
    });
    try {
      showToast("Scan Started on $target");
      final nmapOutput = await sendCommandtoServer(command);
      saveScan(nmapOutput);
    } catch (e) {
      showToast("Error executing scan: $e");
    } finally {
      setState(() {
        isScanning = false;
      });
    }
  }

  Future<void> saveScan(String nmapOutput) async {
    String output = selectedOutput ?? 'txt';
    String fileExtension = '.txt';
    final outputFolder = await getApplicationDocumentsDirectory();
    final String outputFolderPath = outputFolder.path;
    switch (output) {
      case '-oN':
        fileExtension = '.txt';
        break;
      case '-oX':
        fileExtension = '.xml';
        break;
      case '-oG':
        fileExtension = '.grepable';
        break;
      case 'txt':
        fileExtension = '.txt';
        break;
    }
    final now = DateTime.now();
    final fileName = 'scan_result_${now.millisecondsSinceEpoch}$fileExtension';
    final filePath = '${outputFolder.path}/$fileName';
    final file = File(filePath);
    try {
      await file.create(recursive: true);
      await file.writeAsString(nmapOutput);
      showToast('File Saved to $outputFolderPath');
    } catch (e) {
      showToast("Scan Failed");
    }
  }

  void showToast(String message) {
    Fluttertoast.showToast(
      msg: message,
      toastLength: Toast.LENGTH_SHORT,
      gravity: ToastGravity.BOTTOM,
      backgroundColor: Colors.black.withOpacity(0.8),
      textColor: Colors.white,
      fontSize: 16.0,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text("Network Analyzer"),
        actions: [
          IconButton(
            icon: const Icon(Icons.terminal_outlined),
            onPressed: () async {
              final newServer = await showDialog<String>(
                context: context,
                builder: (context) => AlertDialog(
                  title: const Text('Server Address'),
                  content: TextField(
                    controller: serverController,
                    decoration: InputDecoration(
                      hintText: "Enter server address",
                      border: OutlineInputBorder(
                        borderSide:
                            const BorderSide(color: Colors.black, width: 1),
                        borderRadius: BorderRadius.circular(11),
                      ),
                      enabledBorder: OutlineInputBorder(
                        borderSide: BorderSide(color: Colors.black, width: 1),
                        borderRadius: BorderRadius.circular(11),
                      ),
                    ),
                  ),
                  actions: [
                    TextButton(
                      child: const Text('Cancel'),
                      onPressed: () => Navigator.pop(context),
                    ),
                    TextButton(
                        child: const Text('Save'),
                        onPressed: () {
                          setState(() {
                            serverAddress = serverController.text;
                          });
                          Navigator.pop(context);
                        }),
                  ],
                ),
              );
              if (newServer != null) {
                setState(() {
                  serverAddress = newServer;
                });
              }
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.only(
                top: 6.0,
                left: 6.0,
                right: 6.0,
                bottom: 0.0,
              ),
              child: TextField(
                controller: commandController,
                decoration: InputDecoration(
                  labelText: 'Command',
                  contentPadding: const EdgeInsets.all(16.0),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10.0),
                    borderSide:
                        const BorderSide(color: Colors.grey, width: 1.0),
                  ),
                ),
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(6.0),
              child: TextField(
                controller: targetController,
                decoration: InputDecoration(
                  hintText: 'ip.of.the.target or domain name',
                  labelText: 'Target',
                  contentPadding: const EdgeInsets.all(16.0),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(10.0),
                    borderSide:
                        const BorderSide(color: Colors.grey, width: 1.0),
                  ),
                ),
              ),
            ),
            buildDropdownRow('Target Specification', targetSpecOptions,
                'Host Discovery', hostDiscoveryOptions, (value) {
              setState(() {
                selectedTargetSpec = value;
                updateCommand();
              });
            }, (value) {
              setState(() {
                selectedHostDiscovery = value;
                updateCommand();
              });
            }),
            buildDropdownRow('Scan Techniques', scanTechOptions,
                'Port Specification', portSpecOptions, (value) {
              setState(() {
                selectedScanTech = value;
                updateCommand();
              });
            }, (value) {
              setState(() {
                selectedPortSpec = value;
                updateCommand();
              });
            }),
            buildDropdownRow('Service Detection', serviceVersionOptions,
                'OS Detection', osDetectionOptions, (value) {
              setState(() {
                selectedServiceVersion = value;
                updateCommand();
              });
            }, (value) {
              setState(() {
                selectedOSDetection = value;
                updateCommand();
              });
            }),
            buildDropdownRow('Timing Performance', timingPerformanceOptions,
                'Firewall IDS Evasion', firewallIDSOptions, (value) {
              setState(() {
                selectedTimingPerformance = value;
                updateCommand();
              });
            }, (value) {
              setState(() {
                selectedFirewallIDS = value;
                updateCommand();
              });
            }),
            buildDropdownRow('Output', outputOptions, 'Misc', miscOptions,
                (value) {
              setState(() {
                selectedOutput = value;
                updateCommand();
              });
            }, (value) {
              setState(() {
                selectedMisc = value;
                updateCommand();
              });
            }),
            buildDropdownRow(
                'Script', scriptOptions, 'Script List', scriptlistOptions,
                (value) {
              setState(() {
                selectedOutput = value;
                updateCommand();
              });
            }, (value) {
              setState(() {
                selectedMisc = value;
                updateCommand();
              });
            }),
            Padding(
              padding: const EdgeInsets.only(top: 6.0),
              child: ElevatedButton(
                onPressed: () {
                  startScan();
                },
                style: ElevatedButton.styleFrom(
                  fixedSize: const Size(200, 60),
                  backgroundColor: Colors.green,
                  foregroundColor: Colors.white,
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
                child: isScanning
                    ? CircularProgressIndicator(color: Colors.white)
                    : Text('Scan',
                        style: TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                            fontSize: 20)),
              ),
            ),
          ],
        ),
      ),
      bottomNavigationBar: BottomNavigationBar(
        items: const [
          BottomNavigationBarItem(
            icon: Icon(
              Icons.visibility,
              color: Colors.grey,
            ),
            label: "NMAP",
          ),
          BottomNavigationBarItem(
            icon: Icon(
              Icons.article_outlined,
              color: Colors.grey,
            ),
            label: "SCAN RESULT",
          ),
        ],
        currentIndex: 0,
        onTap: (index) {
          if (index == 0) {
            Navigator.pushReplacement(
              context,
              MaterialPageRoute(builder: (context) => const Networkanalyzer()),
            );
          } else if (index == 1) {
            Navigator.pushReplacement(
              context,
              MaterialPageRoute(builder: (context) => const ScanResult()),
            );
          }
        },
      ),
    );
  }

  Widget buildDropdownRow(
      String label1,
      List<String> options1,
      String label2,
      List<String> options2,
      ValueChanged<String?> onChanged1,
      ValueChanged<String?> onChanged2) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8.0),
      child: Row(
        children: [
          Expanded(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 6.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(label1),
                  DropdownButtonFormField2<String>(
                    decoration: InputDecoration(
                      isDense: true,
                      contentPadding: EdgeInsets.zero,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(5),
                      ),
                    ),
                    isExpanded: true,
                    hint: const Text('Select'),
                    items: options1
                        .map((item) => DropdownMenuItem<String>(
                              value: item,
                              child: Text(item),
                            ))
                        .toList(),
                    onChanged: onChanged1,
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 6.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(label2),
                  DropdownButtonFormField2<String>(
                    decoration: InputDecoration(
                      isDense: true,
                      contentPadding: EdgeInsets.zero,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(5),
                      ),
                    ),
                    isExpanded: true,
                    hint: const Text('Select'),
                    items: options2
                        .map((item) => DropdownMenuItem<String>(
                              value: item,
                              child: Text(item),
                            ))
                        .toList(),
                    onChanged: onChanged2,
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class ScanResult extends StatefulWidget {
  const ScanResult({super.key});

  @override
  State<StatefulWidget> createState() {
    return ScanResultState();
  }
}

class ScanResultState extends State<ScanResult> {
  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 3,
      child: Scaffold(
        appBar: AppBar(
          title: const Text("Network Analyzer"),
          bottom: const TabBar(
            labelColor: Colors.black,
            indicatorColor: Colors.black,
            labelStyle: TextStyle(
              fontFamily: 'Sans-Serif',
              fontSize: 11,
            ),
            unselectedLabelStyle: TextStyle(
              fontFamily: 'Roboto',
              fontSize: 9,
            ),
            tabs: [
              Tab(
                icon: Icon(Icons.code_off),
                text: "XML",
              ),
              Tab(
                icon: Icon(Icons.list_alt),
                text: "TEXT",
              ),
              Tab(
                icon: Icon(Icons.assignment),
                text: "GREPABLE",
              ),
            ],
          ),
        ),
        body: const TabBarView(
          children: [
            ScanFileList(extension: 'xml'),
            ScanFileList(extension: 'txt'),
            ScanFileList(extension: 'grepable'),
          ],
        ),
        bottomNavigationBar: BottomNavigationBar(
          items: const [
            BottomNavigationBarItem(
              icon: Icon(
                Icons.visibility,
                color: Colors.grey,
              ),
              label: "NMAP",
            ),
            BottomNavigationBarItem(
              icon: Icon(
                Icons.article_outlined,
                color: Colors.grey,
              ),
              label: "SCAN RESULT",
            ),
          ],
          currentIndex: 0,
          onTap: (index) {
            if (index == 0) {
              Navigator.pushReplacement(
                context,
                MaterialPageRoute(
                    builder: (context) => const Networkanalyzer()),
              );
            } else if (index == 1) {
              Navigator.pushReplacement(
                context,
                MaterialPageRoute(builder: (context) => const ScanResult()),
              );
            }
          },
        ),
      ),
    );
  }
}

class ScanFileList extends StatefulWidget {
  final String extension;
  const ScanFileList({required this.extension, Key? key}) : super(key: key);

  @override
  State<ScanFileList> createState() => _ScanFileListState();
}

class _ScanFileListState extends State<ScanFileList> {
  List<File> allFiles = [];
  List<File> filteredFiles = [];
  TextEditingController searchController = TextEditingController();
  bool isLoading = true;

  @override
  void initState() {
    super.initState();
    loadFiles();
    searchController.addListener(onSearchChanged);
  }

  @override
  void dispose() {
    searchController.dispose();
    super.dispose();
  }

  Future<void> loadFiles() async {
    final directory = await getApplicationDocumentsDirectory();
    final files = directory
        .listSync()
        .whereType<File>()
        .where((file) => file.path.endsWith(widget.extension))
        .toList();

    setState(() {
      allFiles = files;
      filteredFiles = files;
      isLoading = false;
    });
  }

  void onSearchChanged() {
    final query = searchController.text.toLowerCase();
    setState(() {
      filteredFiles = allFiles
          .where(
              (file) => file.path.split('/').last.toLowerCase().contains(query))
          .toList();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.all(8.0),
          child: TextField(
            controller: searchController,
            decoration: InputDecoration(
              labelText: 'Search files',
              prefixIcon: const Icon(Icons.search),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
          ),
        ),
        Expanded(
          child: filteredFiles.isEmpty
              ? const Center(child: Text('No files found.'))
              : ListView.builder(
                  itemCount: filteredFiles.length,
                  itemBuilder: (context, index) {
                    final file = filteredFiles[index];
                    return ListTile(
                      title: Text(file.path.split('/').last),
                      onTap: () {
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (context) => ScanDetailPage(file: file),
                          ),
                        );
                      },
                      trailing: IconButton(
                        icon: const Icon(Icons.share),
                        onPressed: () async {
                          await Share.shareXFiles(
                            [XFile(file.path)],
                            text:
                                'Sharing scan result file: ${file.path.split('/').last}',
                          );
                        },
                      ),
                    );
                  },
                ),
        ),
      ],
    );
  }
}

class ScanDetailPage extends StatelessWidget {
  final File file;
  const ScanDetailPage({required this.file, super.key});

  @override
  Widget build(BuildContext context) {
    final extension = file.path.split('.').last;
    return Scaffold(
      appBar: AppBar(
        title: Text(file.path.split('/').last),
      ),
      body: FutureBuilder<String>(
        future: file.readAsString(),
        builder: (context, snapshot) {
          if (!snapshot.hasData) {
            return const Center(child: CircularProgressIndicator());
          }
          final content = snapshot.data!;
          if (extension == 'xml') {
            return SingleChildScrollView(child: Text(content));
          } else if (extension == 'txt' || extension == 'grepable') {
            return SingleChildScrollView(child: Text(content));
          } else {
            return const Center(child: Text("Unsupported format"));
          }
        },
      ),
    );
  }
}
