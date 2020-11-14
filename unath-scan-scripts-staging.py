#!/usr/bin/env python
from pprint import pprint
import time
from zapv2 import ZAPv2
import sys
from urllib.parse import urlparse

# The URL of the application to be tested
#target = 'http://192.168.1.14:5000'
# Change to match the API key set in ZAP, or use None if the API key is disabled
apiKey = 'ronoskey'
scanPolicyName='obb-ssrf'
exclude_from_scan_regex = ['.*\.css$', '.*\.css$', '.*\.png$', '.*\.js$', '.*\.gif$', '.*\.jpg$', '.*\.jpeg$','.*\.ico$']
zap = ZAPv2(apikey=apiKey)

def do_spider(target,contextname):
	print('Spidering target {}'.format(target))
	# The scan returns a scan id to support concurrent scanning
	scanID1 = zap.spider.scan(target,contextname=contextname)
	timeout = time.time() + 60*10 
	while int(zap.spider.status(scanID1)) < 100:
			# Poll the status until it completes
			if time.time() > timeout:
				break
			print('Spider progress %: {}'.format(zap.spider.status(scanID1)))
			time.sleep(1)
	print('Spider has completed!')

def do_ajaxscan(target,contextname):
	print('Ajax Spider target {}'.format(target))
	scanID = zap.ajaxSpider.scan(target,contextname=contextname)
	timeout = time.time() + 60*4   # 4 minutes from now
	# Loop until the ajax spider has finished or the timeout has exceeded
	while zap.ajaxSpider.status == 'running':
			if time.time() > timeout:
					break
			print('Ajax Spider status' + zap.ajaxSpider.status)
			time.sleep(2)

	print('Ajax Spider completed')
	#print('\n'.join(map(str, zap.ajaxSpider.results(scanID))))
	ajaxResults = zap.ajaxSpider.results(start=0, count=100)
	#print(ajaxResults);

def do_activescan(target,scanpolicyname):
	print('Active Scanning target {}'.format(target))
	for regex in exclude_from_scan_regex:
		zap.ascan.exclude_from_scan(regex)

	scanID2 = zap.ascan.scan(target, scanpolicyname = scanpolicyname)
	while int(zap.ascan.status(scanID2)) < 100:
			# Loop until the scanner has finished
			print('Scan progress %: {}'.format(zap.ascan.status(scanID2)))
			time.sleep(5)
	print('Active Scan completed')
	# Print vulnerabilities found by the scanning
	print('Hosts: {}'.format(', '.join(zap.core.hosts)))

with open(sys.argv[1]) as f:
	for target in f.read().splitlines():
		print('[+] Testing target ' + target + '\n')
		#create new session
		zap.core.new_session(name="mySession", overwrite=True)
		#access url
		zap.core.access_url(url=target, followredirects=True)
		time.sleep(2)

		#include target in Default Context
		o = urlparse(target)
		target_scope = o.scheme + "://"+ o.netloc
		target_scope_regx = target_scope + ".*"
		print(target_scope_regx)
		zap.context.include_in_context(contextname="Default Context",regex=target_scope_regx)
		#zap.context.include_in_context(contextname="Default Context",regex=target+".*")
		do_ajaxscan(target_scope,'Default Context')
		do_spider(target_scope,'Default Context')
		do_activescan(target_scope,scanPolicyName)
		report_filename = './report_' + o.hostname + "__" + str(o.port) + '.html'
		report_file = open(report_filename,"w")
		try:
			report_file.write(zap.core.htmlreport())
		except (RuntimeError, TypeError, NameError, UnicodeEncodeError):
			print('[-] Error during write to file')
		report_file.close()

