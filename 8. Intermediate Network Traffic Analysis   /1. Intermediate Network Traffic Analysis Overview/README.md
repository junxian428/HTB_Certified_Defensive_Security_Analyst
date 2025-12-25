<h3>Intermediate Network Traffic Analysis Overview</h3>

The importance of mastering network traffic analysis in our fast-paced, constantly evolving, and intricate network environments cannot be overstated. Confronted with an overwhelming volume of traffic traversing our network infrastructure, it can feel daunting. Our potential to feel ill-equipped or even overwhelmed is an inherent challenge we must overcome.

In this module, our focus will be on an extensive set of attacks that span crucial components of our network infrastructure. We will delve into attacks that take place on the link layer, the IP layer, and the transport and network layers. Our exploration will even encompass attacks that target the application layer. The goal is to discern patterns and trends within these attacks. Recognizing these patterns equips us with the essential skills to detect and respond to these threats in an efficacious manner.

Further, we will discuss additional skills to augment our abilities. We will touch upon anomaly detection techniques, delve into facets of log analysis, and investigate some Indicators of Compromise (IOCs). This comprehensive approach not only bolsters our capacity for proactive threat identification but also enhances our reactive measures. Ultimately, this will empower us to identify, report, and respond to threats more effectively and within a shorter time frame.

Note: For participating in this module and completing the hands-on exercises, please download pcap_files.zip from the Resources section (upper right corner).

You can download and uncompress pcaps.zip to a directory named pcaps inside Pwnbox as follows.

@htb[/htb]$ wget -O file.zip 'https://academy.hackthebox.com/storage/resources/pcap_files.zip' && mkdir tempdir && unzip file.zip -d tempdir && mkdir -p pcaps && mv tempdir/Intermediate_Network_Traffic_Analysis/* pcaps/ && rm -r tempdir file.zip
--2023-08-08 14:09:14--  https://academy.hackthebox.com/storage/resources/pcap_files.zip

Resolving academy.hackthebox.com (academy.hackthebox.com)... 104.18.20.126, 104.18.21.126, 2606:4700::6812:147e, ...

Connecting to academy.hackthebox.com (academy.hackthebox.com)|104.18.20.126|:443... connected.

HTTP request sent, awaiting response... 200 OK

Length: 19078200 (18M) [application/zip]
