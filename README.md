## Log Collection and Forwarding to Microsoft Sentinel

In this phase of project we will set up a log collector for the firewall, set up honeypot and then forward all logs to Microsoft Sentinel for centralized analysis. By the end of this, we'll have a fully integrated logging system feeding real-time data into Sentinel.

### 1) Setting Up the Log Collector for the Firewall

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
![3 ceh connector](https://github.com/user-attachments/assets/bdf16408-a6f3-4cab-9c51-8b0266bfceee)
2. Open the connector page and create a **Data Collection Rule (DCR)**:
   - In the **Resources** tab, select the log collector VM.
![3 2 ceh dcr](https://github.com/user-attachments/assets/bebdebf0-8084-4c64-89fa-432531c7708e)

- In the **Collect** tab, uncheck "Collect messages without PRI header" and set the minimum log level for each facility.
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
![5 pa content](https://github.com/user-attachments/assets/0a3fb16a-466c-4b9f-9bf9-5254059e18be)

2. Navigate to **Workbooks** and install the **Palo Alto Overview** workbook.
![5 1 pa workbook](https://github.com/user-attachments/assets/6398e999-efd7-42a9-9da2-170d395e46c1)

This dashboard provides a great visual overview of firewall activity, including traffic trends, security threats, and system performance. So far, no threat logs are available—because we haven’t configured detection policies and not exposed any hosts to risk yet. That will come later when we test threat detection capabilities.
![5 3 pa workbook](https://github.com/user-attachments/assets/49874b08-b1d8-420e-b1f1-2a22bea28056)
![5 4 pa workbook](https://github.com/user-attachments/assets/361472d1-b950-4a12-954f-958d769e6cee)
