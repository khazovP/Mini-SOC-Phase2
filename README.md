In this phase of our Project we will set up a Log Collector for FW, Honeypot and configure log forwarding to Sentinel.

1) Log collector for FW
First we need to create policy, which allows Debian's package manager "apt-get" traffic. 
(screenshot)
Install rsyslog
sudo apt-get install rsyslog

Open /etc/rsyslog.conf and uncomment following lines. This will ensure rsyslog daemon is able to receive logs on 514 TCP and UDP

# provides UDP syslog reception
module(load="imudp")
input(type="imudp" port="514")
# provides TCP syslog reception
module(load="imtcp")
input(type="imtcp" port="514")

(screenshot)

Set a time-zone for rsyslog daemon and restart it:
sudo timedatectl set-timezone Europe/Warsaw
sudo systemctl restart rsyslog

(screenshot)

Try to send some test logs to see if it works:
tail -f /var/log/syslog
logger "test log testapp 10:00PM 22-02-25"
(screenshot)
 
Enable autostart for rsyslog:
systemctl enable rsyslog.service

1.2) Configure FW to send logs to log collector.
Device -> Server Profiles -> Syslog -> Add new
Configure server's name, IP address, port and format.
(screenshot)
Go to "Custom Log Format" tab. Here we can specify... a custom log format - we will leverage this feature to send log in CEF (Common Event Format). For every LOG TYPE (traffic, threat, etc) we need to change default format to CEF. Thankfully PA has prepared everything for us, so just copy log format for every log type from Palo Alto docs https://docs.paloaltonetworks.com/resources/cef
(screenshot)

Navigate to Objects -> Log Forwarding Profile. Here create a match list for every traffic type with our syslog server profile as a forwarding method.
(screenshot)

Now, all we need to do - is set this forwarding profile in every policy.
(screenshot)

Commit the change and let's see if traffic arrives at log collector.
(screenshot)

1.3) Now it's time to finaly send logs to Sentinel SIEM for centralized logging and analysis. 
Navigate to Sentinel -> Content Hub and install "Common Event Format (CEF) via AMA" data connector. Open connector page and create new Data Collection Rule (DCR). 
- In Resources tab select log collector VM; 
(screenshot)
- In Collect tab uncheck "Collect messages without PRI header" and set minimum log level for every facility. 
(screenshot)
- After creating DCR, copy agent setup command and paste to our log collector.
(screenshot)

After few minutes, we should see our logs arriving to Sentinel SIEM. We can verify this by issuing this simple query:
Heartbeat
| where TimeGenerated > ago(1h)
| where Computer contains "Host2"
| summarize count() by Computer
(screenshot)

And check amount of logs:
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| summarize LogCount = count()
(screenshot)

1.4) In content hub we can find some ready rules and workbooks, let's set up them.

Look for "Palo Alto PAN-OS" 
(screenshot)
and install "Palo Alto overview" workbook
(screenshot)

Now we have a nice dashboard with statistics about our FW. Threat logs are not yet available, because we have not configured it and not exposed any host to risk.

2) Honeypot
For Honeypot I decided to use a popular one called "Cowrie", which is a medium to high interaction SSH and Telnet honeypot designed to log brute 
force attacks and the shell interaction performed by the attacker.

Since our Honeypot is in DMZ network, we need to do a DNAT to forward incoming ssh session to our Honeypot. However, this was not enough - traffic was not reaching Honeypot. After quick troubleshooting I thought that maybe Azure has problem when traffic is ingressed and egressed on the same interface, so we also need to create a SNAT to trick Azure into thinking that traffic originated from FW. But this makes no sense, as we will not see real attacker's IP. So I decided to move our Honeypot to another subnet - Private1 for example. 
Warning! Putting applications like Honeypot in Trusted zone is security risk, but acceptable, since we are not in production environment and just doing a lab.

2.1) Installation steps are available at official docs: https://docs.cowrie.org/en/latest/INSTALL.html
Again, before proceeding with installation, we need to allow "apt-get" and "github" traffic from our Host.

Let's configure cowrie according to our needs. Specify sensor name (would appear in queries), hostname (which attacker will see after logging in), 
(screenshot)

I decided to use UserDB method for testing, as it allows setting login:password combination for ssh, so I can log in effortlessly and check all logging fields.
(screenshot)

Cowrie has a lot of features, like creating files and commands for attacker to see and use, and even proxying ssh connection to another host. But we will not dive deep into honeypot features in this lab, because we are limited by Azure free-tier.

Let's test if cowrie is working. 
Start cowrie "./cowrie/bin/cowrie start" and start reading log file "tail -f cowrie/var/log/cowrie/cowrie.json"
Try to ssh to Host1 " ssh test@10.0.30.15 -p 2222". 
(screenshot)
As we can see, cowrie is doing it's job! In logs can see password combination and even commands issued by attacker.
(screenshot)

2.2) Honeypot logs

Since by default cowrie logs events in JSON format, we need to use "Custom Logs via AMA" data connector. 
In Resources tab select our Honeypot VM.
In Collect tab specify a new table name (where logs will be stored), a path to log file (/home/cowrie/cowrie/var/log/cowrie/cowrie.json) and trasform query. After long trial and error (remember I'm working with Azure for the first time), I figured out correct transformation string, so JSON gets parsed and table columns are populated correctly.
(transform query)

Now let's wait a few minutes for logs to ingest. This query can help us verify if agent is online.
(hertbeat query)

Now type just table name in query. And we can see the logs!
(screenshot)

As you can see, all event information is stored in RawData columns. But in order to see it in normal way, we need a parsing query. Thankfully, developers have provided us with it. https://github.com/cowrie/cowrie/blob/main/docs/sentinel/cowrie-parser.txt
It needs a little correction, since we do not have "Computers" column, so just remove it from query.
(screenshot)

Also, developers have provided us with a nice workbook for sentinel. 
https://github.com/cowrie/cowrie/blob/main/docs/sentinel/cowrie_workbook.json
It also needs adjustments, as queries inside of it are not parsing JSON. Adjust every query to do it.
(screenshot)

And Voila! We have a nice dashboard with statistics.
(screenshot)

Let's reconfigure cowrie to allow login after random amount of attempts. This will allow login after 20-100 amount of attempts.
Comment out:
#auth_class = UserDB
Uncomment
auth_class = AuthRandom
auth_class_parameters = 20, 100, 100
(screenshot)

2.2) Create appropriate security and NAT policies for Honeypot
Create a DNAT to forward incoming traffic (ports 22 and 2222) to Honeypot port 2222 (default port which cowrie listens on).
(screenshot)
Create Security Policy allowing port 22 and 2222 to firewalls public interface (Should policy contain a pre-NAT or post-NAT ip? There a rule for Palo, which says "Pre NAT IP and Post NAT everything else".
(screenshot)

However, traffic still cannot reach Honeypot. After long troubleshooting session I came to conclusion that Azure may be blocking packet with public IP in source as as kind of IP spoofing protection. Source NAT resolved the issue, but again we are not able to see attackers IP. At this point we are left with two choice: assign public IP to Honeypot and bypass firewall inspection or create a query that would corelate traffic from firewall and show real attackers IP. I decided to move on with easier solution. 

Change ssh port of our Honeypot VM to 8222, so it does not overlap with cowrie.
Add iptables 22 -> 2222 to translate incoming ssh session to port cowrie listens on.
Install ufw and allow 22,2222 from anywhere and 8222 from vpn. Change azure routing, so Private1 has default route pointing not to VirtualAppliance, but to "Internet". 
Attach public IP to Honeypot VM and we are ready!

Everything is set up. Let our Mini SOC run for 24h. Hopefully we get someone trapped in Honeypot. 
Thankfully there is always someone scanning ssh ports :D
(screenshot)

I started cowrie at 20:40
