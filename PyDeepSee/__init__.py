"""
	License: GPLv2
	
	Python bindings for Solera DeepSee forensics tool
"""

import requests,sys,math,pprint
from datetime import datetime, timedelta

class PyDeepSee:
	def __init__(self,server,username,password,verify=True):
		self.server=server
		self.username=username
		self.password=password
		self.verify=verify

	def solRequest(self,location):
		r=requests.get('https://'+self.server+'/ws/'+location, auth=(self.username, self.password), verify=self.verify)
		print r.url
		if r.status_code != 200:
			print r.url
			print r.status_code
			print "Something is wrong. Either we can not connect or there is an issue with the user"
			return False
			sys.exit(0)

		if r.headers.get('content-disposition'):
			return r.text
		else:
			print '\033[33m'
			pprint.pprint(r.json()['response'])
			print '\033[0m'
			return r.json()['response']

	def	testConnect(self):
		result = self.solRequest('config.json')
		print "\033[1;32mSuccesfully authenticated to "+self.server
		print "DeepSee Version: "+result['version']+"\033[0m"
		return True

	"""
		Initiate a report
		Returns the report_id
	"""
	def startReport(self,start,end,report,searchFilter=''):
		r = self.solRequest('deepsee-report-start.json?path=/timespan/'+start.isoformat()+'_'+end.isoformat()+'/'+searchFilter+'&field='+report)
		return r

	"""
		Here is where our report information is at
	"""

	def startLast15min(self):
		end = datetime.now()
		start = end-timedelta(minutes=15)
		report = 'Application'
		return self.startReport(start,end,report)

	"""
		Return raw report status
	"""
	def reportStatus(self,reportID):
		r = self.solRequest('deepsee-report-status.json?report_id='+str(reportID))
		return r

	"""
		See if specific reportID is done
		Returns True or False
	"""
	def reportDone(self,reportID):
		status = self.reportStatus(reportID)
		if status['percentage'] == '100':
			return True
		else:
			return False


	"""
		Return raw report results
	"""
	def reportResult(self,reportID,pageSize=1000):
		pages = 1
		if pageSize > 1000:
			pages = math.ceil(pageSize) + 1
		r = self.solRequest('deepsee-report-results.json?report_id='+str(reportID)+'&page='+str(pages)+'&pageSize='+str(pageSize))
		return r

		
	"""
		Returns raw interfaces
	"""
	def interfaceStatus(self):
		r = self.solRequest('interface-capture-status.json')
		return r


	"""
		Returns array of active interfaces
	"""
	def activeInterfaces(self):
		ifcList = self.interfaceStatus()
		activeList = []
		for interface in sorted(ifcList):
			if ifcList[interface] == True:
				activeList.append(interface)
		return activeList



