#!/usr/bin/env python
from pprint import pprint
import time
from zapv2 import ZAPv2
scanPolicyName='ScriptOnly'
# The URL of the application to be tested
target = 'http://192.168.1.14:5080'
report_filename = '/root/report_' + target.split('/')[2] + '.html'
# Change to match the API key set in ZAP, or use None if the API key is disabled
apiKey = 'ronoskey'

# By default ZAP API client will connect to port 8080
zap = ZAPv2(apikey=apiKey)
# Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
# zap = ZAPv2(apikey=apikey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})

#access url
zap.core.access_url(url=target, followredirects=True)
time.sleep(2)

#include target in Default Context
zap.context.include_in_context(contextname="Default Context",regex=target+".*")

print('Ajax Spider target {}'.format(target))
scanID = zap.ajaxSpider.scan(target,contextname='Default Context')

timeout = time.time() + 60*2   # 2 minutes from now
# Loop until the ajax spider has finished or the timeout has exceeded
while zap.ajaxSpider.status == 'running':
    if time.time() > timeout:
        break
    print('Ajax Spider status' + zap.ajaxSpider.status)
    time.sleep(2)

print('Ajax Spider completed')
#print('\n'.join(map(str, zap.ajaxSpider.results(scanID))))
ajaxResults = zap.ajaxSpider.results(start=0, count=100)
print(ajaxResults);
# If required perform additional operations with the Ajax Spider results


print('Active Scanning target {}'.format(target))
scanID2 = zap.ascan.scan(target, scanpolicyname = scanPolicyName)
while int(zap.ascan.status(scanID2)) < 100:
    # Loop until the scanner has finished
    print('Scan progress %: {}'.format(zap.ascan.status(scanID2)))
    time.sleep(5)

print('Active Scan completed')
# Print vulnerabilities found by the scanning
print('Hosts: {}'.format(', '.join(zap.core.hosts)))
#print('Alerts: ')
#print(zap.core.alerts(baseurl=target))

print(zap.core.htmlreport())
report_file = open(report_filename,"w")
report_file.write(zap.core.htmlreport())
report_file.close()
#zap.exportreport.generate(absolutepath="/root/", fileextension= html, sourcedetails = )