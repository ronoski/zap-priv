"""
The scanNode function will typically be called once for every page 
The scan function will typically be called for every parameter in every URL and Form for every page 

Note that new active scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"  
"""
payloads = ['{{77*77}}', '{77*77}', '#set($run=77*77) $run', '${77*77}', '[77*77]', '${{77*77}}', '[@(77*77)]', '}}{{77*77}}', '{#77*77}', '[[77*77]]', '}{77*77}', '{@77*77}', '{{=77*77}}', '<%= 77*77 %>', '#{ 77 * 77}']
positive_responses = ['5929', '5,929', 'error', 'Error' ,'Exception', 'trace', 'Expecting', 'SyntaxError', 'syntax error' ,'Syntax Error', 'at line', 'At line', 'At Line']
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

  # Copy requests before reusing them
  for payload in payloads: 
  msg_clone = msg.cloneRequest();

    # setParam (message, parameterName, newValue)
    sas.setParam(msg_clone, param, payload);

    # sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    sas.sendAndReceive(msg_clone, True, True);
  res_body_str = msg_clone.getResponseBody().toString()
    # Test the response here, and make other requests as required
    if any(pos_res in res_body_str for pos_res in positive_responses ) and msg.getResponseHeader().getStatusCode() != 404 :
    # Change to a test which detects the vulnerability
     # raiseAlert(risk, int reliability, String name, String description, String uri, 
     #    String param, String attack, String otherInfo, String solution, String evidence, 
     #    int cweId, int wascId, HttpMessage msg)
    # risk: 0: info, 1: low, 2: medium, 3: high
     # reliability: 0: falsePassitive, 1: suspicious, 2: warning
        sas.raiseAlert(3, 2, 'Server Side Template Injection', 'Server Side Template Injection Detected', msg_clone.getRequestHeader().getURI().toString(), param, payload, 'Any other info', 'The solution ', '' , 0, 0, msg_clone);