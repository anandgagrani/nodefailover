
C7000 Blades –How to migrate to Hot Stand by Blade /Compute if dedicated OS Host fails.


Objective
To ensure that via HPE Monitor Scripts, If either of the Host ( in 4 Node Cluster of KVM), any of the Dedicated OS Host fails , Hot Stand-by Blade /Compute will take over as part of failover process.

Process flow
 


Prerequisites
1.	1 x C7000 enclosure with 4 BL460 g9/g10 blades.
2.	1 x Oneview virtual appliance that is monitoring c7000 enclosure and servers.
3.	The Oneview profiles are created on 4 blades with boot disk from SAN and 3 nodes (that are being monitored) are installed with RHEL OS and are configured to be part of cluster.
4.	1 x Test Server/VM running Linux (CentOS 7)to excute migration scripts in same subnet as c7000 blades.
5.	Yum update the above VM with latest patches and proceed with following steps on same VM:
•	RUN $Install Python 3.6, python-pip
•	RUN $pip3 install > redfish, hponeview>=4.7.0
•	Download the HPE provided zip file for the scripts and place in dir  ~/BSNL_cluster_failover_POC/.
•	Directory structure should look like following:
 [root@appliance-vm BSNL_cluster_failover_POC]# ll
total 44
-rw-r--r--. 1 root root 16107 Jul 19 00:26 failback_node.py
-rw-r--r--. 1 root root 24330 Jul 25 03:04 failover_node.py
drwxr-xr-x. 2 root root    60 Jul 23 03:17 inputs
-rw-r--r--. 1 root root  2472 Jul 23 03:37 README.md

•	Edit ./inpus/failover_config.json and update it with Oneview credentials and hardware names of nodes to be monitored and the name of standby hardware.
 

6.	1 x windows VM running the Traptool to generate the alerts on Oneview SCMB bus for simulating critical alerts for scripts to work like realtime.


 


 














Scripts and Paths
Ensure that all the HPE scripts (as part of attachment) , be unzipped and placed in CentOS VM. Following is an example of the paths we used in our lab setup.
Execution / input scripts:
1.	~/BSNL_cluster_failover_POC /failover_node.py                - This is master script that monitors alerts and migrates profile from failed to standby hardware

2.	~/BSNL_cluster_failover_POC /failback_node.py                 - This is master script that migrates back profile from standby hardware to failback  hardware.

3.2.	~/BSNL_cluster_failover_POC /inputs/failover_config.json – This is the input file for master script failover_node.py. It contains oneview credentials and hardware to monitor and standby hardware names.

4.	~/BSNL_cluster_failover_POC /inputs/failback_config.json – This is the input file for master script failback_node.py. It contains standby hardware and failback hardware names.

5.3.	~/ BSNL_cluster_failover_POC /internal/_failbackservice_template  - This file acts as template file to create systemd service. and failback_node.py

6.4.	~/BSNL_cluster_failover_POC /create_failover_service.sh – This shell script takes service name as command line parameter and create systemd service. Later service keeps monitoring for hardware failures.

7.5.	~/BSNL_cluster_failover_POC /logs/BSNL_failover_failback_<OneView IP>.log  - This log file gets generated when you run master scripts failover_node.py and failback_node.py
and failback_node.py


Action flow
1.	Set the desired hardware names to monitor in following file:
$ vim ~/BSNL_cluster_failover_POC /inputs/failover_config.json
{
        "oneview_config": {
                "host": "<OneView IP> ",
                "user": "Administrator",
                "passwd": "PASSWORD",
                "authLoginDomain": "local",
                "fail_severity": "critical",
                "hardwares_to_monitor": ["Rack3-C7000, bay 5", "Rack3-C7000, bay 6","Rack3-C7000, bay 7"],
                "standby_hardware": "Rack3-C7000, bay 8"
        },
        "logging_level": "INFO"
}


2.	Execute the master script failover_node.py from VM:

$ python3 failover_node.py
This command would read the input  file “failover_config.json” and would first check the health of the hardware (primary and standby) and then starts watching the server hardwares via OneView SCMB bus for any critical alerts:

 

















3.	Check from Oneview GUI the current state of the hardware (before failover migration):  The node3 profile is running on bay7 now. Our standby node is on bay8.

 





4.	Run the following command on the RHEL cluster node to see the health of the cluster(before failure of one node). 
It shows all nodes ONLINE.

$ pcs cluster status

 
















5.	Now to SIMULATE a real hardware critical alert (eg: Processor failure) - Trigger the SNMP trap on OneView SCMB bus using the traptool > Send Trap button. This would cause the master script to proceed with profile migration. 

 




6.	Run the following command on the RHEL cluster node to see the health of the cluster(when due to critical alert the node is powered down by master script as part of migration in step shown below ).  It shows 2 nodes ONLINE and 1 OFFLINE:

 













7.	As soon as the critical alert is received on the server hardware, the master script would initiate failover process from failed hardware to standby hardware. The script also shows the migration time taken. 

 





















8.	Once the master script completes the migration / failover as shown in step above, please check the log file for steps performed and errors.
 




9.	Now run the following command on the RHEL cluster node to check the cluster health. It shows all 3 nodes ONLINE again.

                
	








10.	Check from OneView GUI the profile is migrated to new standby hardware (after migration is complete): The node3 profile which was running on bay7 earlier is now running on bay8.

 








Results:
Using the master failover script, we were able to migrate host profile (SAN storage as well) from a failed node to a standby node successfully and RHEL cluster rebuilds itself with new standby node.In this case it took approximately 9 minutes for migration.

Once the failover is successfully completed the script still continues to run and keep monitoring for critical alerts.

Now failed server acts as standby server but no failover occurs until it is fixed.

If any active hardware fails failover occurs if standby server is healthy else the error will be logged saying that “Aborted failover as the standby server was unhealthy”

Script can also be run as linux service.


Troubleshooting / Extras:
1.	The script bundle also contains failback.py and its respective input failback_config Jason files incase you wish to migrate back from standbay node to primary node after the primary node is replace with fixed hardware.


