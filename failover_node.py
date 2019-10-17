# -*- coding: utf-8 -*-
###
# (C) Copyright (2018) Hewlett Packard Enterprise Development LP
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
###

import sys
if sys.version_info < (3, 6):
	print('Incompatible version of Python, Please use Python ver 3.6 and above..!')
	sys.exit(1)

import argparse
import json
import ssl
import logging
import os
from datetime import datetime

from time import sleep
from functools import partial
import amqplib.client_0_8 as amqp

## HPE OneView library
from hpOneView.oneview_client import OneViewClient
from hpOneView.resources.task_monitor import TaskMonitor
from hpOneView.exceptions import HPOneViewException

# Initialize variables
input_file = os.getcwd() + os.sep + "inputs/failover_config.json"
input_data = None
config = None



def read_file(filename):
	try:
		# Parsing for OneView arguments   
		fp = open(input_file, 'r')
		data = json.loads(fp.read())
			
		# Validate the data in the OneView config files.
		fp.close()
		return data
	
	except Exception as e:
		logging.error("Error in config files. Check and try again. msg={}".format(e))
		raise Exception("Error in config files. Check and try again. msg={}".format(e))

input_data = read_file(input_file)
config = input_data['oneview_config']

def write_config_to_input_file(config):
	global input_file
	global input_data
	input_data['oneview_config'] = config
	try:
		with open(input_file, 'w') as outfile:
			json.dump(input_data, outfile, indent=4)

	except Exception as e:
		print("\nError writing config file. Check and try again. msg={}\n".format(e))
		logging.error("Error writing config files. Check and try again. msg={}".format(e))		



#################################################################
# Function to update server hardware powerState.
# 
#################################################################
def update_server_powerstate(oneview_client, hardware_uri, power_state):
	if power_state.lower() == 'on':
		configuration = {
			"powerState": "On",
			"powerControl": "MomentaryPress"
		}
	else:
		configuration = {
			"powerState": "Off",
			"powerControl": "PressAndHold"
		}
	try:
		# Make the update call
		response = oneview_client.server_hardware.update_power_state(configuration, hardware_uri)
		# logging.info("Changed the power state of server '{name}' to '{powerState}'".format(**response))
		# print("\nChanged the power state of server '{name}' to '{powerState}'".format(**response))
		
	except Exception as e:
		logging.debug("Failed to update server powerstate. msg: {}".format(e.msg))

#################################################################
# Function 
# 
#################################################################	
def monitor_profile_update(oneview_client, task):
	task_monitor = TaskMonitor(oneview_client.connection)
	# Flag that sets if atleast one task is in running state
	running_flag = True

	# Create a toolbar to monitor creation of profiles 
	toolbar_width = 100

	# setup toolbar
	sys.stdout.write("\n\t\t\t\t[%s]" % (" " * toolbar_width))
	sys.stdout.flush()
	sys.stdout.write("\b" * (toolbar_width+1)) # return to start of line, after '['

	prevPercentComplete = 0
	while running_flag:
		running_flag = False
		percentComplete = 0
		runningCount = 0
		if task_monitor.is_task_running(task):
			# Set the flag if atleast one task is running
			running_flag = True
			# Get the percent completed 
			percentComplete += task_monitor.get(task)['percentComplete']
			runningCount += 1

		if runningCount > 0:
			percentComplete = percentComplete/runningCount
		else:
			percentComplete = 100
		percentDiff = percentComplete - prevPercentComplete
		prevPercentComplete = percentComplete
		# Update toolbar
		print("#"*int(percentDiff), end='')
		sys.stdout.flush()
		
		#print("percentComplete : {} %".format(percentComplete))
		sleep(10)
				
	sys.stdout.write("]\n") 
	sys.stdout.flush()

	TASK_COMPLETED_STATES = ['Warning', 'Completed']
	TASK_ERROR_STATES = ['Error', 'Terminated', 'Killed']		 

	task = task_monitor.get(task)
	profile_name = task['associatedResource']['resourceName']
	if task['taskState'] in TASK_ERROR_STATES:
		msg = None
		error_code = None
		if 'taskErrors' in task and len(task['taskErrors']) > 0:
			err = task['taskErrors'][0]
			if 'message' in err:
				msg = err['message']
			error_code = err.get('errorCode')

		logging.info("\nFailed to update server profile - \"{}\".\n\tError msg: {}".format(profile_name, msg))
		raise Exception("\nFailed to update server profile - \"{}\".\n\tError msg: {}".format(profile_name, msg))
		
	# if task['taskState'] in TASK_COMPLETED_STATES:
		# print("\nSuccessfully updated server profile - \"{}\"".format(profile_name))	

##################################################################
# Function to 
##################################################################	
def unassign_profile_from_failed_hardware(oneview_client, failed_hardwareUri):

	# Get failed server hardware body
	failed_server_hardware = oneview_client.server_hardware.get(failed_hardwareUri)

	# Get server profile
	profile_uri = failed_server_hardware['serverProfileUri']
	if not profile_uri:
		raise Exception("Failed Server hardware has no profile applied. Aborting.. ")
	server_profile = oneview_client.server_profiles.get(profile_uri)

	# Power off the failed server hardware 
	print("\n\t\t\t1a) Powering off failed server hardware.")
	logging.info("\t\t\t1a) Powering off failed server hardware.")

	update_server_powerstate(oneview_client, failed_hardwareUri, "Off")
	
	print("\n\t\t\t1b) Unassigning server profile from the failed hardware.")
	logging.info("\t\t\t1b) Unassigning server profile from the failed hardware.")

	server_profile.pop('serverHardwareUri', None)
	server_profile.pop('enclosureBay', None)
	server_profile.pop('enclosureUri', None)

	# ret = oneview_client.server_profiles.update(server_profile, profile_uri, force=True)
	# profile_uri += '?force=True'
	# print(profile_uri)
	task, resp = oneview_client.connection.put(profile_uri ,server_profile)
	monitor_profile_update(oneview_client, task)
	# print(ret)
	
	return failed_server_hardware['name'], server_profile['name'], profile_uri

##################################################################
# Function to 
##################################################################
def assign_profile_standby_hardware(oneview_client, profile_uri, standby_hardware_name):

	standby_hardware_det = oneview_client.server_hardware.get_by('name', standby_hardware_name)
	if not standby_hardware_det:
		raise Exception("Couldn't find the standby server hardware. Please check the input file and retry.")
	standby_hardware = standby_hardware_det[0]
	if standby_hardware['state'] == "ProfileApplied":
		raise Exception("Standby server hardware already has profile applied. Aborting.. ")
	standby_hardware_uri = standby_hardware['uri']
	# et profile body 
	server_profile = oneview_client.server_profiles.get(profile_uri)
	
	# Power off standby server hardware 
	update_server_powerstate(oneview_client, standby_hardware_uri, "Off")
	
	# Assign profile to standby server hardware
	print("\n\t\t\t2a) Assigning server profile to Standby server hardware - \"{}\"".format(standby_hardware_name))
	logging.info("\t\t\t2a) Assigning server profile to Standby server hardware - \"{}\"".format(standby_hardware_name))

	server_profile['serverHardwareUri'] = standby_hardware_uri
	server_profile['serverHardwareTypeUri'] = standby_hardware['serverHardwareTypeUri']
	# ret = oneview_client.server_profiles.update(server_profile, profile_uri, force=True)
	# profile_uri += '?force=True'
	# print(profile_uri)
	task, resp = oneview_client.connection.put(profile_uri ,server_profile)
	monitor_profile_update(oneview_client, task)
	
	# Power on standby server hardware 
	print("\n\t\t\t2b) Powering on standby hardware")
	logging.info("\t\t\t2b) Powering on standby hardware")

	update_server_powerstate(oneview_client, standby_hardware_uri, "On")
	
##################################################################
# Function to 
##################################################################
def is_standby_hardware_healthy(oneview_client, standby_hardware_name):
	standby_hardware_det = oneview_client.server_hardware.get_by('name', standby_hardware_name)
	if not standby_hardware_det:
		logging.error("Couldn't find the standby server hardware. Aborting Fail-over, please check the input file and retry.")
		return False

	standby_hardware = standby_hardware_det[0]
	if standby_hardware['state'] == "ProfileApplied":
		logging.error("Standby server hardware already has profile applied. Aborting Fail-over.. ")
		return False

	if standby_hardware['status'].lower() not in ('ok', 'warning'):
		logging.error("Standby server hardware is not healthy. Aborting Fail-over.. ")
		return False

	return True

##################################################################
# Function to 
##################################################################	
def migrate_profile(oneview_client, failed_hardwareUri, standby_hardware_name):
	## Unassign profile from failed hardware
	print("\n\t\t(1/2) Unassign profile from failed hardware")
	logging.info("\t\t(1/2) Unassign profile from failed hardware")

	failed_hardware, profile_name, profile_uri = unassign_profile_from_failed_hardware(oneview_client, failed_hardwareUri)
	
	print("\n\t\t(2/2) Assign profile to standby hardware")
	logging.info("\t\t(2/2) Assign profile to standby hardware")

	assign_profile_standby_hardware(oneview_client, profile_uri, standby_hardware_name)
	print("\n\t\tServer Profile \"{}\" successfully migrated from failed hardware \"{}\" to standby hardware\"{}\""\
		.format(profile_name, failed_hardware, standby_hardware_name))

	logging.info("\tServer Profile \"{}\" successfully migrated from failed hardware \"{}\" to standby hardware\"{}\""\
		.format(profile_name, failed_hardware, standby_hardware_name))

##################################################################
# Function to 
##################################################################
def check_if_hardware_failed(alert):
	health_category = alert["resource"]['healthCategory']
	state = alert['newState']

	interested_health_categories = ['Network', 'FibreChannel', 'Storage', 'Thermal', 'Memory', 'Power', 'Processor', 'BIOS']
	interested_health_categories = [a.lower() for a in interested_health_categories]
	# Test
	# state = 'Active'
	# print(alert)
	if ( health_category.lower() in interested_health_categories ) and ( state == 'Active' ):
		return True
	else:
		return False

##################################################################
# Function to 
##################################################################
def failover_node(oneview_client, alert):
	global config
	hardware_failed = check_if_hardware_failed(alert)
	if hardware_failed:
		description = alert['resource']['description']
		corrective_action = alert['resource']['correctiveAction']
		status = alert['resource']['severity']
		# Get failed server hardware 
		failed_hardware = alert["resource"]["associatedResource"]["resourceName"]
		# print("\nFailed hardware: \"{}\"".format(failed_hardware))
		failed_hardwareUri = alert["resource"]["associatedResource"]["resourceUri"]
		 
		# get standby server hardware 
		standby_hardware_name = config['standby_hardware']
		
		print("\n\tServer hardware failure detected...")
		logging.info("\tServer hardware failure detected...")
		
		print("\n\t\tFailed hardware: \"{}\"\n\t\tStatus: \"{}\"".format(failed_hardware, status))
		logging.info("\t\tFailed hardware: \"{}\"".format(failed_hardware))
		logging.info("\t\tStatus: \"{}\"".format(status))

		print("\n\t\tDescription: {}\n\t\tResolution: {}".format(description, corrective_action))
		logging.info("\t\tDescription: {}".format(description))
		logging.info("\t\tResolution: {}".format(corrective_action))

		print("\n\tFail-over initiated...")
		startTime = datetime.now().replace(microsecond=0) 
		logging.info("\tFail-over initiated...")
		print("\n\t\tStandby hardware: \"{}\".".format(standby_hardware_name))
		logging.info("\t\tStandby hardware: \"{}\".".format(standby_hardware_name))

		if is_standby_hardware_healthy(oneview_client, standby_hardware_name):
			# Start Fail-over 
			migrate_profile(oneview_client, failed_hardwareUri, standby_hardware_name)

			# Update hardwares to monitor
			hardwares_to_monitor = config['hardwares_to_monitor']
			hardwares_to_monitor.remove(failed_hardware)
			hardwares_to_monitor.append(standby_hardware_name)
			config['hardwares_to_monitor'] = hardwares_to_monitor 

			# Update Standby hardware
			config['standby_hardware'] = failed_hardware

			write_config_to_input_file(config)

			endTime = datetime.now().replace(microsecond=0) 
			timeDelta = str(endTime - startTime).split(':')
			print("\n\t\tTime taken: {} Hrs, {} Mins".format(timeDelta[0], timeDelta[1]))
			logging.info("\t\tTime taken: {} Hrs, {} Mins".format(timeDelta[0], timeDelta[1]))

			print("\nFail-over successfully completed.Please check the cluster status from OS.\n")
			logging.info("Fail-over successfully completed.Please check the cluster status.")

			logfile = os.getcwd() + os.sep + "logs" + os.sep +"BSNL_failover_failover_{}.log".format(config['host'])
			print("\nPlease chect the logs here: \"{}\"\n".format(logfile))
		else:
			logging.error("Could not perform Fail-over due to unhealthy standby hardware")
			print("\n\tCould not perform Fail-over due to unhealthy standby hardware\n")


##################################################################
# Main callback function. When alert comes to OneView we are 
# notified via this callback. 
##################################################################	
def callback(channel, oneview_client,  msg):
	global config
	# ACK receipt of message
	channel.basic_ack(msg.delivery_tag)

	# Convert from json into a Python dictionary
	alert = json.loads(msg.body)
	# print(alert)
	resourceCategory = alert["resource"]["associatedResource"]["resourceCategory"]
	resourceName = alert["resource"]["associatedResource"]["resourceName"]
	alertSeverity = alert["resource"]["severity"]
	#print(resourceCategory, resourceName, alertSeverity)
	# is_failover = False
	if (resourceCategory == "server-hardware") and (resourceName in config['hardwares_to_monitor']):
		if alertSeverity.lower() == config["fail_severity"]:
			# print(alert)
			# is_failover = failover_node(oneview_client, alert, config)
			failover_node(oneview_client, alert)
			# failover_node(oneview_client, alert, config)
	
	# Cancel this callback
	# if msg.body == 'quit':
	# if is_failover:
		# channel.basic_cancel(msg.consumer_tag)

		
##################################################################
# Listening to messages over SCMB. 
#
##################################################################	
def recv(oneview_client, route):
	
	host = config['host']
	# Create and bind to queue
	EXCHANGE_NAME = 'scmb'
	dest = host + ':5671'

	# Setup our ssl options
	ssl_options = ({'ca_certs': 'certs/' + host + '-caroot.pem',
					'certfile': 'certs/' + host + '-client.pem',
					'keyfile': 'certs/' + host + '-key.pem',
					'cert_reqs': ssl.CERT_REQUIRED,
					'ssl_version' : ssl.PROTOCOL_TLSv1_1,
					'server_side': False})

	logging.info(ssl_options)

	# Connect to RabbitMQ
	conn = amqp.Connection(dest, login_method='EXTERNAL', ssl=ssl_options)
	
	ch = conn.channel()
	qname, _, _ = ch.queue_declare()
	routeArray = route.split(';')
	for each in routeArray:
		logging.info("SCMB bind to " + each)
		ch.queue_bind(qname, EXCHANGE_NAME, each)
	ch.basic_consume(qname, callback=partial(callback, ch, oneview_client))
	print("\nConnection established to SCMB/OneView(IP: {}). Monitoring for server hardware failure...\n".format(config['host']))
	logging.info("Connection established to SCMB/OneView(IP: {}). Monitoring for server hardware failure...\n".format(config['host']))

	while ch.callbacks:
		ch.wait()
		
	ch.close()
	# TODO: close scmb connection
	try:
		conn.close()
	except:
		pass


##################################################################
# Initialize certs dir.
##################################################################
def initialize_certs():
	# Create certs directory for storing the OV certificates
	certpath=os.getcwd() + os.sep + "certs"
	if not os.path.exists(certpath):
			os.makedirs(certpath)

##################################################################
# Generate RabbitMQ certs.
##################################################################
def genRabbitCa(oneview_client):
	# logging.info('genRabbitCa')
	try:
		certificate_ca_signed_client = {
			"commonName": "default",
			"type": "RabbitMqClientCertV2"
		}
		oneview_client.certificate_rabbitmq.generate(certificate_ca_signed_client)
	except Exception as e:
		logging.warning("Error in generating RabbitMQCa.")
		logging.warning(e)

##################################################################
# Get RabbitMQ CA cert
##################################################################
def getCertCa(oneview_client, host):
	# logging.info('getCertCa')
	cert = oneview_client.certificate_authority.get()
	ca = open('certs/' + host + '-caroot.pem', 'w+')
	ca.write(cert)
	ca.close()

##################################################################
# Get RabbitMQ KeyPair.
##################################################################			
def getRabbitKp(oneview_client, host):
	try:
		cert = oneview_client.certificate_rabbitmq.get_key_pair('default')
	except Exception as e:
		if e.msg == 'Resource not found.':
			genRabbitCa(oneview_client)
			cert = oneview_client.certificate_rabbitmq.get_key_pair('default')
	ca = open('certs/' + host + '-client.pem', 'w+')
	ca.write(cert['base64SSLCertData'])
	ca.close()
	ca = open('certs/' + host + '-key.pem', 'w+')
	ca.write(cert['base64SSLKeyData'])
	ca.close()



def acceptEULA(oneview_client):
	# logging.info('acceptEULA')
	# See if we need to accept the EULA before we try to log in
	eula_status = oneview_client.connection.get_eula_status()
	try:
		if eula_status is True:
			oneview_client.connection.set_eula('no')
	except Exception as e:
		logging.error('EXCEPTION: {}'.format(e))

##################################################################
# Init the logging module.
##################################################################
def initialize_logging(oneViewIP, loggingLevel='WARNING'):
	# Initialize the log file path, log format and log level
	logfiledir = os.getcwd() + os.sep + "logs"
	if not os.path.isdir(logfiledir):
		os.makedirs(logfiledir)

	logfile = logfiledir + os.sep +"BSNL_failover_failback_{}.log".format(oneViewIP)
	if os.path.exists(logfile):
		fStats = os.stat(logfile) 
		if fStats.st_size >= 1024000:
			#Backing up logfile if size is more than 1MB
			timestamp = '{:%Y-%m-%d_%H_%M}'.format(datetime.now())
			#Backup logfile
			os.rename(logfile,logfiledir + os.sep + 'BSNL_failover_{}_'.format(oneViewIP)+ timestamp +".log")
			#Create empty logfile
			open(logfile, 'a').close()
	else:
		#Create empty logfile
		open(logfile, 'a').close()

	# Init the logging module with default log level to INFO. 
	logging.basicConfig(filename=logfile, format='%(asctime)s - %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s', datefmt='%d-%m-%Y:%H:%M:%S', level=loggingLevel)
	
	return logfile
##################################################################
# Function - 
# 
##################################################################
def get_hardwares_info(oneview_client, hardwares_to_monitor):
	hardwares_info = []
	for hardware in hardwares_to_monitor:
		data = {}
		srv_hardware = oneview_client.server_hardware.get_by('name', hardware)
		if not srv_hardware:
			print("\n\tCould find server hardware \"{}\". Please check the input file and retry.\nAborting...".format(hardware))
			logging.error("\tCould find server hardware \"{}\". Please check the input file and retry.\nAborting...".format(hardware))
			exit(1)
		else:
			hardware_details = srv_hardware[0]
			
		if hardware_details['state'] != "ProfileApplied":
			print("\n\tServer hardware \"{}\"has no profile applied. Aborting.. ".format(hardware))
			logging.error("\tServer hardware \"{}\"has no profile applied. Aborting.. ".format(hardware))
			exit(1)
		data['hardwareName'] = hardware_details['name']
		data['hardwareStatus'] = hardware_details['status']
		
		profile_uri = hardware_details['serverProfileUri']
		server_profile = oneview_client.server_profiles.get(profile_uri)
		data['serverProfileName'] = server_profile['name']
		data['serverprofileStatus'] = server_profile['status']
		hardwares_info.append(data)
		
	return hardwares_info
	
	
##################################################################
# Function - validate inputs
# 
##################################################################
def validate_hardwares(oneview_client, config):
	print("\nValidating inputs...")
	logging.info("Validating inputs...")

	hardwares_to_monitor = config['hardwares_to_monitor']
	standby_hardware = config['standby_hardware']
	print("\n\n\t(1/2) Validating hardware to be monitored...")
	logging.info("\t(1/2) Validating hardware to be monitored...")

	hardwares_info = get_hardwares_info(oneview_client, hardwares_to_monitor)
	for hardware in hardwares_info:
		print("\n\t\t Hardware: \"{}\";\tStatus: \"{}\"".format(hardware['hardwareName'],hardware['hardwareStatus']))
		logging.info("\t\t Hardware: \"{}\";\tStatus: \"{}\"".format(hardware['hardwareName'],hardware['hardwareStatus']))

		print("\t\t Profile: \"{}\";\tStatus: \"{}\"".format(hardware['serverProfileName'],hardware['serverprofileStatus']))
		logging.info("\t\t Profile: \"{}\";\tStatus: \"{}\"".format(hardware['serverProfileName'],hardware['serverprofileStatus']))
		
	print("\n\n\t(2/2) Validating standby server hardware...")
	logging.info("\t(2/2) Validating standby server hardware...")
	
	standby_hardware_details = oneview_client.server_hardware.get_by('name', standby_hardware)
	if not standby_hardware_details:
		print("\n\tCould find standby server hardware \"{}\". Please check the input file and retry.\nAborting...".format(standby_hardware))
		logging.error("\tCould find standby server hardware \"{}\". Please check the input file and retry.\nAborting...".format(standby_hardware))
		exit(1)
	standby_hardware_details = standby_hardware_details[0]
	if standby_hardware_details['state'] == "ProfileApplied":
		print("\n\tStandby server is already having profile applied, Please change the standby hardware and retry.\nAborting...")
		logging.error("\tStandby server is already having profile applied, Please change the standby hardware and retry.\nAborting...")
		exit(1)
	if standby_hardware_details['status'].lower() not in ("ok", "warning"):
		print("\n\tHealth : Not OK.")
		logging.error("\tHealth : Not OK.")

		print("\n\tStandby server hardware \"{}\" status is not in ['OK', 'Warning'].Aborting...".format(standby_hardware))
		logging.error("\tStandby server hardware \"{}\" status is not in ['OK', 'Warning'].Aborting...".format(standby_hardware))
		exit(1)
	standby_hardware_uri = standby_hardware_details['uri']
	print("\n\t\tHardware Name : \"{}\"\n\t\tStatus : {}\n".format(standby_hardware, standby_hardware_details['status']))
	logging.info("\t\tHardware Name : \"{}\"\t\tStatus : {}\n".format(standby_hardware, standby_hardware_details['status']))

	return standby_hardware_uri

##################################################################
# Main function.
# 
##################################################################
def main():
	global input_data
	global config
	print("#"*150)
	# input_file = os.getcwd() + os.sep + "inputs/failover_config.json"
	# Valid alert types sent by Oneview. This is used to compare the user input "alert_type" from oneview.json file
	alertTypes = ['Ok','Warning','Critical','Unknown']
	# try:
	# 	# Parsing for OneView arguments   
	# 	fp = open(input_file, 'r')
	# 	data = json.loads(fp.read())
			
	# 	# Validate the data in the OneView config files.
	# 	config = data["oneview_config"]
			
	
	# except Exception as e:
	# 	print("\nError in config files. Check and try again. msg={}\n".format(e))
	# 	logging.error("Error in config files. Check and try again. msg={}".format(e))

	# 	sys.exit(1)

	# Get the logging level and init the logging module
	loggingLevel = input_data["logging_level"].upper()
	logfile = initialize_logging(config['host'], loggingLevel)

	config['fail_severity'] = config["fail_severity"].lower()

	alertTypes = [a.lower() for a in alertTypes] # List of permissible alerts
	
	if not config['fail_severity'] in alertTypes:
		# print(alertType, alertTypes)
		logging.error("Fail severity  mismatch : " + config['fail_severity'] + ". Kindly review and restart the plugin.")
		sys.exit(1)
	elif not config['fail_severity']:
		logging.error("Enter the hardware fail severity  in config file. Exiting...")
		sys.exit(1)

	# Create certs directory for storing the OV certificates
	initialize_certs()

	ovConfig = {
		"ip": config["host"],
		"credentials": {
			"userName": config["user"],
			"authLoginDomain": config["authLoginDomain"],
			"password": config["passwd"]
		}
	}

	# print("attempting to connect OneView")
	try:
		oneview_client = OneViewClient(ovConfig)
		acceptEULA(oneview_client)
		
	except Exception as e:
		logging.error("Error connecting to appliance. Check for OneView details in input json file.")
		logging.error(e)
		raise Exception("Error connecting to appliance. Check for OneView details in input json file.")
		
	# print("Connected to OneView.")
	
	standby_hardwareUri = validate_hardwares(oneview_client, config)
	# exit()
	# Download the certificates
	getCertCa(oneview_client, config["host"])
	getRabbitKp(oneview_client, config["host"])
	
	# Start listening for messages.
	recv(oneview_client, "scmb.alerts.#")
	print("#"*150)


if __name__ == '__main__':
	sys.exit(main())


