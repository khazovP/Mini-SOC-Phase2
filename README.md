## FW Log Collection and Forwarding to Microsoft Sentinel

In this phase of project we will set up a log collector for the firewall, set up honeypot and then forward all logs to Microsoft Sentinel for centralized analysis. By the end of this, we'll have a fully integrated logging system feeding real-time data into Sentinel.

### 1) Setting Up Log Collector for the Firewall

#### 1.1) Installing and Configuring Rsyslog

First things first—before we can collect logs, we need to make sure our log collector can actually receive them. This starts with allowing creating policy for Debian's package manager (`apt-get`) to access the necessary repositories.

![1 5 debian apt rule](https://github.com/user-attachments/assets/a264aa7c-1a83-4736-8910-f4b3b55de489)

Next, let's install `rsyslog` on the log collector VM:

```bash
sudo apt-get install rsyslog
```

Now, we need to configure `rsyslog` to accept logs over TCP and UDP. Open the configuration file `/etc/rsyslog.conf` and uncomment the following lines:

```bash
# provides UDP syslog reception
#module(load="imudp")
#input(type="imudp" port="514")

# provides TCP syslog reception
#module(load="imtcp")
#input(type="imtcp" port="514")
```

![1 7 debian rsyslog config](https://github.com/user-attachments/assets/0054f951-0782-4200-9b7d-fffb6a3a4704)

To avoid timestamp issues, let's set the time zone and restart the service:

```bash
sudo timedatectl set-timezone Europe/Warsaw
sudo systemctl restart rsyslog
```

![1 9 debian rsyslog status](https://github.com/user-attachments/assets/67498344-c946-46d2-8794-bbda8d2b6cb1)

At this point, it's a good idea to check if everything is working as expected. We can send a test log message:

```bash
tail -f /var/log/syslog
logger "test log testapp 10:00PM 22-02-25"
```

![1 11 debian rsyslog test](https://github.com/user-attachments/assets/c6753bcc-68b5-4f52-aac5-4cf162fd8a82)

Finally, to make sure `rsyslog` starts automatically after a reboot, run:

```bash
systemctl enable rsyslog.service
```

#### 1.2) Configuring the Firewall to Send Logs

Now that our log collector is up and running, we need to configure the firewall to send logs to it.

1. Go to **Device > Server Profiles > Syslog** and add a new profile.
2. Set the server's name, IP address, port (514), and log format (BSD).

![2 1 syslog profile](https://github.com/user-attachments/assets/6c101397-02b3-4052-a895-8350f498803d)

3. Move to the **Custom Log Format** tab. This is where we configure the firewall to send logs in **CEF (Common Event Format)**, a structured log format that makes parsing easier. Fortunately, Palo Alto Networks provides predefined CEF formats for different log types, so we don’t have to build them from scratch.
4. 
   - [Palo Alto CEF Log Format Documentation](https://docs.paloaltonetworks.com/resources/cef)

Copy log format for every traffic type into corresponding field.

![2 1 1 syslog profile format](https://github.com/user-attachments/assets/4d939579-928b-47eb-8921-8a10e96a5161)

![2 1 2 syslog profile format](https://github.com/user-attachments/assets/91b0e0f0-34de-493e-a200-448fa216c9c7)

![2 1 3 syslog profile format](https://github.com/user-attachments/assets/fe3e3c0d-13cd-4cac-b884-8d432422d567)

4. Next, go to **Objects > Log Forwarding Profile** and create match lists for different log types, selecting our syslog server as the forwarding destination.

![2 2 forwarding profile](https://github.com/user-attachments/assets/e3a9f512-7d6b-4733-8ac7-164022e45689)

![2 2 1 forwarding profiles](https://github.com/user-attachments/assets/ee788a80-1fdb-49a5-854d-528218e91758)

5. Apply this log forwarding profile to all security policies.

![2 3 policy log profile](https://github.com/user-attachments/assets/28f1065d-354e-495d-b45d-25f979884653)

6. Commit the changes and check if logs are reaching the log collector.
```bash
tail -f /var/log/syslog
```
![2 5 debian syslog test](https://github.com/user-attachments/assets/33d7286c-5ead-4be4-93aa-de490f085831)

### 1.3) Forwarding Logs to Microsoft Sentinel

With logs successfully arriving at the collector, it's time to forward them to Sentinel for advanced analysis.

1. In **Microsoft Sentinel**, navigate to **Content Hub** and install the **Common Event Format (CEF) via AMA** data connector.
2. 
![3 ceh connector](https://github.com/user-attachments/assets/bdf16408-a6f3-4cab-9c51-8b0266bfceee)
3. Open the connector page and create a **Data Collection Rule (DCR)**:
   - In the **Resources** tab, select the log collector VM.
   - 
![3 2 ceh dcr](https://github.com/user-attachments/assets/bebdebf0-8084-4c64-89fa-432531c7708e)

- In the **Collect** tab, uncheck "Collect messages without PRI header" and set the minimum log level for each facility.
- 
![3 3 ceh dcr 2](https://github.com/user-attachments/assets/06441b3b-0a59-46fa-93e5-1bdbad183340)

3. Once the DCR is created, copy the agent setup command and execute it on the log collector VM.

*(Insert screenshot of agent installation command and execution output)*

![3 4 debian agent install](https://github.com/user-attachments/assets/689dc349-8e1d-449b-80c0-917478591a1c)

4. At first, logs were not appearing in Sentinel. After some troubleshooting, I noticed blocked traffic in the firewall logs with the application labeled **azure-log-analytics**. The fix was simple—create a policy to allow this traffic. Once that was done, logs started flowing into Sentinel as expected.

*(Insert screenshot of firewall logs showing blocked traffic and new policy allowing it)*

5. To confirm log ingestion, run this KQL query in Sentinel to see if agent is able to connect (agents should send heartbeat every minute):

```kusto
Heartbeat
| where TimeGenerated > ago(1h)
| where Computer contains "Host2"
| summarize count() by Computer
```
![3 6 1 query amount of heartbeats](https://github.com/user-attachments/assets/3cbbb407-8eed-4cc2-9553-d9a2281a0c57)

And this query to see amount of logs:

```kusto
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| summarize LogCount = count()
```
![3 7 query amount of logs ](https://github.com/user-attachments/assets/ff1bc52f-dda6-42a2-a547-42f1e96ab98c)

### 1.4) Configuring Dashboards and Analytics in Sentinel

Let's take advantage of visualization capabilities of Sentinel.

1. In **Content Hub**, install the **Palo Alto PAN-OS** content pack.
2. 
![5 pa content](https://github.com/user-attachments/assets/0a3fb16a-466c-4b9f-9bf9-5254059e18be)

3. Navigate to **Workbooks** and install the **Palo Alto Overview** workbook.
4. 
![5 1 pa workbook](https://github.com/user-attachments/assets/6398e999-efd7-42a9-9da2-170d395e46c1)

This dashboard provides a great visual overview of firewall activity, including traffic trends, security threats, and system performance. So far, no threat logs are available—because we haven’t configured detection policies and not exposed any hosts to risk yet. That will come later when we test threat detection capabilities.

![5 3 pa workbook](https://github.com/user-attachments/assets/49874b08-b1d8-420e-b1f1-2a22bea28056)

![5 4 pa workbook](https://github.com/user-attachments/assets/361472d1-b950-4a12-954f-958d769e6cee)

---

## 2) Honeypot Setup

For the honeypot, Cowrie was chosen due to its popularity and effectiveness. Cowrie is a medium-to-high interaction SSH and Telnet honeypot designed to log brute force attacks and capture attacker activity.

Since the honeypot is placed in a DMZ network, a DNAT rule is required to forward incoming SSH traffic to it. However, this alone was not sufficient—traffic was not reaching the honeypot. After some troubleshooting, I made assumption that Azure does not handle ingress and egress traffic on the same interface well. To work around this, an SNAT rule was introduced to make Azure believe the traffic originated from the firewall. However, this method obscures the attacker's real IP address, which is crucial for analysis. To solve this, the honeypot was moved to another subnet (e.g., `Private1`).

⚠ **Security Warning:** Placing a honeypot in a trusted zone poses a security risk. This approach is acceptable in a lab environment but should be avoided in production.

### 2.1) Installing and Configuring Cowrie

Cowrie installation steps can be found in the official documentation:
[https://docs.cowrie.org/en/latest/INSTALL.html](https://docs.cowrie.org/en/latest/INSTALL.html)

Before proceeding, a firewall policy must be created to allow outbound traffic for `apt-get` and `gitHub` from the honeypot host.

#### Configuring Cowrie

- Open cowrie configuration file.
- Set the **sensor name** (appears in queries) and **hostname** (what the attacker sees upon logging in).
- 
![7 2 honeypot config](https://github.com/user-attachments/assets/fbf584e3-ace8-42a0-878c-5232aed478cd)

- For initial testing, the **UserDB** authentication method was used, allowing a predefined login/password combination for SSH. This made it easier to verify logging functionality.
- 
![7 3 honeypot config](https://github.com/user-attachments/assets/98a7252f-4002-474e-8053-7a1054417992)

Cowrie offers many features, including fake file systems, command emulation, and even proxying SSH connections to another host. However, doe to limited time of Azure free-tier, advanced features were not explored.

#### Testing Cowrie

Start Cowrie and monitor logs:

```bash
./cowrie/bin/cowrie start
tail -f cowrie/var/log/cowrie/cowrie.json
```

Attempt to SSH into the honeypot from another machine:

```bash
ssh test@10.0.30.15 -p 2222
```
Cowrie successfully logs login attempts, credentials, and even commands executed by attackers.

![7 4 honeypot test](https://github.com/user-attachments/assets/df41f8b9-33e1-4318-810d-493fbb5c7a46)

![7 5 honeypot test](https://github.com/user-attachments/assets/f38e4565-c140-4451-938b-e0e94739c6d8)

---

### 2.2) Sending Honeypot Logs to Microsoft Sentinel

Cowrie logs events in JSON format by default, so we need to use Custom Logs via AMA data connector. Cowrie has many logging modules, including syslog and CEF, but I decided to explore how JSON log can be integrated into Sentinel.

1. In Sentinel, navigate to **Content Hub** and select **Custom Logs via AMA**.
2. 
![9 data connector](https://github.com/user-attachments/assets/bbf41349-8497-47e9-8943-8781f0027624)
3. In the **Resources** tab, select the honeypot VM.
5. In the **Collect** tab:
   - Specify a new **table name** for the logs.
   - Set the **log file path** to `/home/cowrie/cowrie/var/log/cowrie/cowrie.json`.
   - Define a **transformation query** to properly parse JSON logs. (I will upload txt file with query to this repo) 
Initially, custom logs are not parsed and come "as they are" in RawData field, so they need to be parsed. After multiple attempts (learning Azure on the go!), the correct transformation query was determined.

![9 1 dcr](https://github.com/user-attachments/assets/90ab54bd-2428-4fa9-8e8e-ec6edab91452)

#### Verifying Log Ingestion

Check if the agent is online byt checking Heartbeat table:

```kusto
Heartbeat
| where TimeGenerated > ago(1h)
| where Computer contains "HoneypotVM"
| summarize count() by Computer
```
![9 2 sentinel cowrie heartbeat](https://github.com/user-attachments/assets/4f84fff8-cb0b-442d-8c8c-adef08c0c6ca)

Then, run a basic query to view logs. This simple query with only table name shows us all logs from this table as they are stored:

```kusto
cowrie_CL
```
![9 2 sentinel cowrie logs](https://github.com/user-attachments/assets/286b802f-06cb-4d75-b79e-a6544287961c)

As we can see log data is stored in the **RawData** column. To extract meaningful information, parsing queries must be used. Thankfully, the developers have provided a ready-to-use parser:

[https://github.com/cowrie/cowrie/blob/main/docs/sentinel/cowrie-parser.txt](https://github.com/cowrie/cowrie/blob/main/docs/sentinel/cowrie-parser.txt)

The query requires a minor adjustment—removing the **Computers** column reference. Run it and we can see parsed logs, with fields such as Source IP, Username, Password etc.
![9 3 sentinel cowrie logs](https://github.com/user-attachments/assets/7d44b7ab-418c-4dd9-8dd5-78407936520f)

#### Setting Up the Sentinel Workbook

Cowrie developers have also provided a pre-built Sentinel workbook:
[https://github.com/cowrie/cowrie/blob/main/docs/sentinel/cowrie\_workbook.json](https://github.com/cowrie/cowrie/blob/main/docs/sentinel/cowrie_workbook.json)

However, the queries in the workbook do not parse JSON logs by default. Each query must be adjusted to properly extract log fields. (I will also upload updated workbook to repo)

![11 workbook query rewrite](https://github.com/user-attachments/assets/69472f18-4066-4ee9-a7ea-9f460566f4d7)

And Voila! We have a nice dashboard with statistics.

![11 1 workbook](https://github.com/user-attachments/assets/07b46e00-29a5-42c4-8158-2da24359ac90)

![11 2](https://github.com/user-attachments/assets/62ee8e66-a550-4897-aef4-38300b991d15)

---

### 2.3) Adjusting Cowrie Authentication

To simulate real-world conditions, I decided to reconfigure honeypot to allow login after a random number of failed attempts. This setting increases realism by mimicking how actual systems respond to brute-force attacks.

Open cowrie config file and modify the authentication settings:

```ini
# Comment out UserDB authentication
# auth_class = UserDB

# Enable randomized authentication attempts
auth_class = AuthRandom
auth_class_parameters = 20, 100, 100
```
![11 3 honeypot config prod](https://github.com/user-attachments/assets/42d1a4a1-403f-44d0-8620-b5c079e9c2b1)

---

### 2.4) Security and NAT Policies for the Honeypot

1. **Create a DNAT Rule**
   - Forward incoming SSH traffic (`ports 22 and 2222`) to the honeypot's `port 2222` (default Cowrie listening port).
   - 
![11 6 NAT rules for host1](https://github.com/user-attachments/assets/ee8c07c2-e65c-4de4-aaaa-eacbf5d1def3)

2. **Create a Security Policy**
   - Allow inbound SSH (`ports 22 and 2222`) to the firewall's public interface.
   - Palo Alto security policy logic for NAT is: p**re-NAT IP, post-NAT everything else**.
(policy on screenshot was temporarily disabled, so no one could interfere during configuration and log cleanup process)

![11 5 security rules for host1](https://github.com/user-attachments/assets/406892a3-aa86-4bf0-bb69-de1f4af3c9d4)


#### Troubleshooting NAT Issues

I faced the same issue as before moving Honeypot to Trust zone. After configuring DNAT, traffic still did not reach the honeypot. After extensive troubleshooting, it made assumption that Azure was blocking packets with public IPs as the source, likely due to anti-spoofing protection (yes, I know, that's pretty illogical). Using SNAT resolved the issue but masked attacker IPs. I was left with two options:

1. **Assign a public IP to the honeypot** (bypassing firewall inspection).
2. **Create a Sentinel query to correlate firewall and honeypot logs** to reconstruct attacker IPs.

For simplicity, I decide to move on with first approach.

---

### 2.5) Final Adjustments and Deployment

1. Change the honeypot VM's SSH port to `8222` (to avoid conflicts with Cowrie).
![15 2](https://github.com/user-attachments/assets/2affe366-d3bc-4ae2-af82-41ab65bb89b2)

3. Use `iptables` to forward traffic from `port 22` to `port 2222`.
![15 3](https://github.com/user-attachments/assets/ed426a94-5d15-499d-ab05-b23dfc36636b)

5. Install `ufw` and allow only following traffic to our Honeypot - this is important, because VM will be exposed to internet:
   ```bash
   ufw allow 22,2222 from anywhere
   ufw allow 8222 from 192.168.100.0/24
   ```
6. Update Azure routing so `Private1` has a default route to **Internet** (not VirtualAppliance).
![15 4](https://github.com/user-attachments/assets/da5b2d50-2e21-4d3d-b85c-bf48adba6692)

8. Attach a **public IP** to the honeypot VM.
---

## Conclusion

Everything is now set up! The honeypot and firewall log collection system is fully operational. I will let it run for some time, waiting for attack attempts. In the meantime, I'll dive deeper into Azure routing issue. 
Hope we can get someone trapped in our Honeypot.
Thankfully, there’s always someone scanning SSH ports! 😃
![13 pa ssh logs](https://github.com/user-attachments/assets/46d0f7a6-6ea3-41d8-bf24-fd61ee61bb09)

## Honeypot Attack Analysis – Insights from 3 Days of Data

I let **Cowrie** run for approximately **three days**, collecting attack data. To better visualize the results, I added a **geolocation map** and a **chart by country** to my dashboard (I will upload queries to repo). 
![1 honeypot](https://github.com/user-attachments/assets/cd14d304-9bd0-47c6-80f7-97d9d1c2adb9)

#### **Top Attack Sources**  
Unsurprisingly, **China** holds the leading position, with **3,000+ authentication attempts** in just three days. (I expected North Korea, but oh well! 😆)  

#### **Brute Force Trends & Common Credentials**  
- **Top username:** `"root"` (This has been the case for years.)
- **Most common passwords:** Simple, unchanged over the years.
- **Conclusion:** Brute-force attacks remain focused on exploiting **basic security flaws**, which, despite being trivial, are still widespread.  
---
![2 honeypot log pass](https://github.com/user-attachments/assets/f74777db-5b92-45be-9c0b-9bb906e5ab42)

## **Interesting Observations**  

### **Automated Scripted Attacks**
Commands are executed **with minimal delay**, indicating they are run as part of a **script or program** rather than manually.  
![3 honeypot commands mikrotik](https://github.com/user-attachments/assets/4742eb8e-17c4-431f-ae4d-e3aa34ca43b2)

#### **MikroTik Router Targeting**  
A suspicious command was frequently executed:  
```bash
/ip cloud print
```
- This checks if **Dynamic DNS (DynDNS)** is configured on a **MikroTik router**.  
- If attackers are building a **botnet of routers**, this command might help them maintain access to devices with **dynamic IPs**.  

#### **Modem & Out-of-Band (OOB) Access Checks**  
Some commands appeared to check for **connected mobile network modems**, which are sometimes used as **out-of-band access** devices:  
```bash
ls -la /dev/ttyGSM* /dev/ttyUSB-mod* /var/spool/sms/* /var/log/smsd.log /etc/smsd.conf* /usr/bin/qmuxd /var/qmux_connect_socket /etc/config/simman /dev/modem* /var/config/sms/*
```  

#### **Cryptominer Detection?**  
One particularly interesting command:  
```bash
ps | grep '[Mm]iner'
ps -ef | grep '[Mm]iner'
```
- This suggests that attackers **check for existing mining software**.  
- Possible explanation: They want to know if the device has **already been compromised by another hacker**.  

---

## **Most Popular Attack Commands**  

The **top executed command** was simple **system reconnaissance**:  
```bash
uname -s -v -n -r -m
```
This suggests that attackers are merely **gathering system info**, likely **profiling vulnerable machines** before deciding on their next steps.  

---
![4 most popular command](https://github.com/user-attachments/assets/8ed4acc7-8c89-4370-8d63-3ab688b3c74d)

## **Brute Force Tools – SSH Client Fingerprinting**  

### **GO-based SSH Brute Force Tool**  
The most common **SSH client fingerprint** in the attacks:  
```plaintext
SSH-2.0-GO
```
- This is from the **Go (Golang) standard SSH library**.  
- No widely known open-source brute-force tool uses this fingerprint, so it could be a **custom or private tool**.  
![5 top client](https://github.com/user-attachments/assets/68d6e272-a760-4305-8353-f337220d85cb)

#### **Correlation Query Findings**  
I created **correlation queries** (with some AI assistance 😏) to analyze this SSH client across different attack sources.  
- The **GO-based SSH client** was the most **widely used across all countries**.
- It appears to be the **preferred tool among almost all attackers**.
![6 honeypot top client by country](https://github.com/user-attachments/assets/6e1cec7b-a7e4-4cea-b638-3677a5619161)

#### **Persistent Attacker Identified**  
- One particular **fingerprint stood out**, generating **significantly more events** than all others.  
- At first, I assumed this was from a **highly active attacker in China**.  
- However, **after running further correlation queries**, I discovered the **real origin**—this attacker is **based in the US**, operating from a **single IP address**.  
![9 top finger identified](https://github.com/user-attachments/assets/31899ebb-ce5a-48a3-b62a-df865e484713)

---

### **Final Thoughts**  
This short experiment confirmed that brute-force attacks remain **highly automated**, with attackers primarily:  
👉 **Scanning for common misconfigurations**  
👉 **Profiling vulnerable systems**  
👉 **Checking for existing infections (miners, botnets, etc.)**  

