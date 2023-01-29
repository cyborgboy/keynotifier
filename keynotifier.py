from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

import re

class BurpExtender(IBurpExtender, IScannerCheck):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()
    callbacks.registerScannerCheck(self)

  def doPassiveScan(self, baseRequestResponse):
    # Check for secrets in request and response
    request = baseRequestResponse.getRequest()
    response = baseRequestResponse.getResponse()

    # Convert request and response to string
    request_str = self._helpers.bytesToString(request)
    response_str = self._helpers.bytesToString(response)

    # List of secrets
    secrets = [
        "api_key",
        "password",
        "aws_access_key_id",
        "aws_secret_access_key",
        "secret_key"
    ]

    issues = []
    for secret in secrets:
      if re.search(secret, request_str) or re.search(secret, response_str):
        issues.append(
            SecretIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [baseRequestResponse],
                "Secret found: " + secret,
                "A potential secret has been found in the request/response: " + secret,
                "High"
            )
        )
    return issues

  def doActiveScan(self, baseRequestResponse, insertionPoint):
    return None
  
  def consolidateDuplicateIssues(self, existingIssue, newIssue):
    if existingIssue.getIssueName() == newIssue.getIssueName():
      return -1
    else:
      return 0

class SecretIssue(IScanIssue):
  def __init__(self, httpService, url, requestResponse, name, detail, severity):
    self._httpService = httpService
    self._url = url
    self._requestResponse = requestResponse
    self._name = name
    self._detail = detail
    self._severity = severity

  def getUrl(self):
    return self._url

  def getIssueName(self):
    return self._name

  def getIssueType(self):
    return 0

  def getSeverity(self):
    return self._severity

  def getConfidence(self):
    return "Certain"

  def getIssueBackground(self):
    return None

  def getRemediationBackground(self):
    return None

  def getIssueDetail(self):
    return self._detail

  def getRemediationDetail(self):
    return None

  def getHttpMessages(self):
    return self._requestResponse

  def getHttpService(self):
    return self._httpService