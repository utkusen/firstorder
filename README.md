```

                .==.     A traffic analyzer to evade Empire's communication            
               ()''()-.       __ _          _                _      
    .---.       ;--; /       / _(_)        | |              | | 
  .'_:___'. _..'.  __'.     | |_ _ _ __ ___| |_ ___  _ __ __| | ___ _ __ 
  |__ --==|'-''' /'...;     |  _| | '__/ __| __/ _ \| '__/ _` |/ _ \ '__|  
  [  ]  :[|       |---/     | | | | |  \__ \ || (_) | | | (_| |  __/ |    
  |__|  =[|     .'    '.    |_| |_|_|  |___/\__\___/|_|  \__,_|\___|_|
  / / ____|     :       '._           
 |-/.____.'      | :       :        by Utku Sen, Gozde Sinturk
/___\ /___\      '-'._----'              TEAR Security 


```


## Abstract

firstorder is designed to evade Empire's C2-Agent communication from anomaly-based intrusion detection systems. It takes a traffic capture file (pcap) of the network and tries to identify normal traffic profile. According to results, it creates an Empire HTTP listener with appropriate options.

## The Idea

Anomaly-based NIDS refers to building a statistical model describing the normal network traffic, and flagging the abnormal traffic. Anomaly-based systems have the advantage of detecting zero-day attacks, since these attacks will be distinguishable from normal traffic. On the other hand, anomaly-based systems require a training phase in order to identify normal network traffic. It is possible to mislead learning algorithm of an anomaly-based system by poisoning the initial data. However in a real-world scenario, it's hard for an attacker to know, when the network is being trained for anomaly detection purposes. Because of that, we have to guess the normal traffic profile.

Empire is a PowerShell and Python based post-exploitation framework which is designed for "assume breach" type of activities. We can describe Empire's workflow in two parts: Agent and listener. Agent states the infected machine on the network which takes and executes given tasks on there. Listener is described as a communication server (C2) in which agent connects there and gets it's task, sends output of the tasks. 

We can list following options of the listener which can be insight of an anomaly-based NIDS:

1) Request URI: Agent makes it's connection to the C2 server with a GET request to a specific URI (for example:"/read.php") If only html or aspx pages are in use in the local network, this "php" extension may flagged by the anomaly detection system

2) User-agent value: User-agent value defines the operating system and browser choice of the agent. For example if all users on the
network uses Microsoft Windows with Chrome, setting user-agent value to macOS with Safari may flagged by the anomaly detection system.

3) Server header: Server header value defines the web server type of the C2. For example if all the servers on the network are using
Linux, setting server header as "Microsoft-IIS" may flagged by the anomaly detection system

4) Port: If only common ports like 80, 443, 8080 are used in the network, selecting communication port as 5839 may flagged by the anomaly
detection system

5) Connection Interval (DefaultDelay): By default, agent will send heartbeat request to the C2 server in every 5 seconds. If regular
users are not connecting to a local server in every 5 seconds, this will be likely to flagged by anomaly detection system.

Our goal is configuring these options in order to normalize Empire's C2-agent communication.

## Usage

firstorder requires Python 2.7 with scapy and requests libraries to work. You can install them with pip:

`pip install scapy requests`

It extracts following information from a pcap file:

-Most used ports

-Most used server headers

-Most used user-agents

-Most used URIs

-How many different machines broadcasted ARP packets (for determining network size)

-How many different machines executed LDAP queries (for determining network size)

If you only pass pcap file as an argument with -f parameter, it analyzes and extracts information from the pcap file but doesn't create an Empire listener.

Command: `python firstorder.py -f file.pcap`

To create an Empire listener according to analyzed data, you need to start the Empire in REST API mode with username and password. For example:

`python empire --rest --username empireadmin --password Password123`

Now, you can start firstorder with following command:

`python firstorder.py -f file.pcap -u empireadmin -p Password123`

It automatically creates a listener named "firstorder" with appropriate options.

Example Output:

```
=== Top 10 Port Statistics ===

Port 443: 1677/5937 (28.25%)
Port 58471: 1107/5937 (18.65%)
Port 80: 536/5937 (9.03%)
Port 58457: 454/5937 (7.65%)
Port 54674: 341/5937 (5.74%)
Port 57859: 228/5937 (3.84%)
Port 54119: 157/5937 (2.64%)
Port 58408: 155/5937 (2.61%)
Port 53: 124/5937 (2.09%)
Port 58403: 80/5937 (1.35%)

=== Top 10 Server Headers ===

Server: PWS/8.3.1.0.4: 9/36 (25.00%)
Server: RocketCache/2.2: 5/36 (13.89%)
Server: nginx: 5/36 (13.89%)
Server: NetDNA-cache/2.2: 4/36 (11.11%)
Server: None: 3/36 (8.33%)
Server: nginx/1.8.1: 2/36 (5.56%)
Server: cafe: 1/36 (2.78%)
Server: Microsoft-IIS/7.5: 1/36 (2.78%)
Server: cloudflare-nginx: 1/36 (2.78%)
Server: Microsoft-IIS/10.0: 1/36 (2.78%)

=== Top 10 User-Agent Headers ===

User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36: 29/32 (90.62%)
User-Agent:  Google Chrome/63.0.3239.84 Mac OS X: 3/32 (9.38%)

=== Top 10 GET Request URI ===

GET request URI: /api/country/: 3/29 (10.34%)
GET request URI: /request: 2/29 (6.90%)
GET request URI: /_1515920640761/redot.js: 1/29 (3.45%)
GET request URI: /widgets/assets/widget/scripts.min.js: 1/29 (3.45%)
GET request URI: /widgets/assets/widget/style.min.css?v=1: 1/29 (3.45%)
GET request URI: /gtm.js?id=GTM-NVDWP6: 1/29 (3.45%)
GET request URI: /static/912a9b7effbdc65cceea05635536577c8b0665f7.js: 1/29 (3.45%)
GET request URI: /widgets/YYN-000399-20160616.html: 1/29 (3.45%)
GET request URI: /async/CreateCookieSSO_Gb: 1/29 (3.45%)

=== Number of Unique IP addresses (ARP)===
16

=== Number of Unique Computer Names(LDAP)===
15

```
