try:
    from config import *
except ImportError:
    print "Error: You must create config.py."
    raise SystemExit()

import base64
import time
import hashlib
import hmac
import urllib
import urllib2
from xml.etree import ElementTree
import argparse
import sys
import os
import json

def create(arguments):
    cmd = argparse.ArgumentParser()
    cmd.add_argument("urls")
    cmd.add_argument("jobfile", nargs='?')
    cmd.add_argument("--title", default="Annotation")
    cmd.add_argument("--description", default="")
    cmd.add_argument("--cost", type=float, default=1)
    cmd.add_argument("--duration", type=int, default=3600 * 5)
    cmd.add_argument("--lifetime", type=int, default=3600*24*7*2)
    cmd.add_argument("--approved-percent", type=int, default=90)
    cmd.add_argument("--approved-amount", type=int, default=100)
    cmd.add_argument("--country-code", default="US")
    cmd.add_argument("--overwrite", default=False, action="store_true")

    args = cmd.parse_args(arguments)

    if args.jobfile is None:
        jobfile = args.urls + ".jobs"
    else:
        jobfile = args.jobfile

    if os.path.exists(jobfile) and not args.overwrite:
        print "Will not overwrite {}".format(jobfile)
        return

    with open(jobfile, "w") as fd:
        for url in open(args.urls):
            url = url.strip()
            res = server.createhit(args.title, args.description, url, args.cost,
                                args.duration, args.lifetime,
                                minapprovedpercent = args.approved_percent,
                                minapprovedamount = args.approved_amount,
                                countrycode = args.country_code)
            fd.write("{}\t{}\n".format(url, res.hitid))
            print "URL={}, HIT={}".format(url, res.hitid) 

def retrieve(arguments):
    cmd = argparse.ArgumentParser()
    cmd.add_argument("jobfile")
    cmd.add_argument("resultdir", nargs='?')

    args = cmd.parse_args(arguments)

    if args.resultdir:
        resultdir = args.resultdir
    else:
        resultdir = args.jobfile + ".results"

    num_assignments = 0

    for line in open(args.jobfile):
        url, hitid = line.strip().split("\t")
        print "HIT={}".format(hitid)

        for assignment in server.getassignments(hitid).assignments:
            assignmentid = assignment.find("AssignmentId").text
            payload = dict((x.tag, x.text) for x in assignment)
            del payload["Answer"]
            payload.update(retrieve_decode_answer(assignment.find("Answer").text))
            print "  Assignment={}".format(assignmentid)
            if not os.path.exists(resultdir):
                os.makedirs(resultdir)
            with open(os.path.join(resultdir, hitid + "_" + assignmentid + ".json"), "w") as fd:
                json.dump(payload, fd, indent=2)
            num_assignments += 1

    print "Retrieved {} completed assignments".format(num_assignments)

def disable(arguments):
    cmd = argparse.ArgumentParser()
    cmd.add_argument("jobfile")

    args = cmd.parse_args(arguments)

    for line in open(args.jobfile):
        url, hitid = line.strip().split("\t")

        try:
            server.disable(hitid)
        except CommunicationError:
            pass
        else:
            print "URL={}, HIT={}".format(url, hitid)

def retrieve_decode_answer(xml):
    resp = {}
    tree = ElementTree.fromstring(xml)
    ns = {"ns": "http://mechanicalturk.amazonaws.com/AWSMechanicalTurkDataSchemas/2005-10-01/QuestionFormAnswers.xsd"}
    for answer in tree.findall("ns:Answer", ns):
        id = answer.find("ns:QuestionIdentifier", ns).text
        data = json.loads(answer.find("ns:FreeText", ns).text)
        resp[id] = data
    return resp

def compensate(arguments):
    cmd = argparse.ArgumentParser()
    cmd.add_argument("resultdir")
    cmd.add_argument("--scan", default=False, action="store_true")

    args = cmd.parse_args(arguments)

    if args.scan:
        for file in os.listdir(args.resultdir):
            if not file.endswith(".json"):
                continue
            hitid, assignmentid = file.split(".")[0].split("_")
            try:
                print "Accept {}".format(assignmentid)
                server.accept(assignmentid)
            except:
                pass
            else:
                print "HIT={}, accept".format(hitid)
    else:
        print "Error: specify --scan"

def status(arguments):
    cmd = argparse.ArgumentParser()
    cmd.add_argument("jobfile", nargs='*', default=None)

    args = cmd.parse_args(arguments)

    if args.jobfile:
        total = 0
        for jobfile in args.jobfile:
            print jobfile
            for line in open(jobfile):
                url, hitid = line.strip().split("\t")
                num = len(server.getassignments(hitid).assignments)
                total += num
                if num > 0:
                    print "{} = {}".format(hitid, num)
        print "Total: {}".format(total)

    print "Balance: {}".format(server.balance)


class MTurkServer(object):
    def __init__(self, signature, accesskey, localhost, sandbox = False):
        self.signature = signature
        self.accesskey = accesskey
        self.localhost = localhost
        self.sandbox = sandbox

        if sandbox:
            self.server = "mechanicalturk.sandbox.amazonaws.com"
        else:
            self.server = "mechanicalturk.amazonaws.com"

    def request(self, operation, parameters = {}):
        """
        Sends the request to the Turk server and returns a response object.
        """

        if not self.signature or not self.accesskey:
            raise RuntimeError("Signature or access key missing")

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        hmacstr = hmac.new(self.signature,
            "AWSMechanicalTurkRequester" + operation + timestamp, hashlib.sha1)
        hmacstr = base64.encodestring(hmacstr.digest()).strip()

        baseurl = "/?" + urllib.urlencode({
                    "Service": "AWSMechanicalTurkRequester",
                    "AWSAccessKeyId": self.accesskey,
                    "Version": "2008-08-02",
                    "Operation": operation,
                    "Signature": hmacstr,
                    "Timestamp": timestamp})
        url = baseurl + "&" + urllib.urlencode(parameters)
        url = "https://" + self.server + url

        req = urllib2.Request(url = url)
        data = urllib2.urlopen(req)
        
        response = MTurkResponse(operation, data)
        return response

    def createhit(self, title, description, page, amount, duration,
        lifetime, keywords = "", autoapprove = 604800, height = 800, maxassignments = 1,
        minapprovedpercent = None, minapprovedamount = None, countrycode = None):
        """
        Creates a HIT on Mechanical Turk.
        
        If successful, returns a MTurkResponse object that has fields:
            hit_id          The HIT ID
            hit_type_id     The HIT group ID

        If unsuccessful, a CommunicationError is raised with a message
        describing the failure.
        """
        r = {"Title": title,
            "Description": description,
            "Keywords": keywords,
            "Reward.1.Amount": amount,
            "Reward.1.CurrencyCode": "USD",
            "AssignmentDurationInSeconds": duration,
            "AutoApprovalDelayInSeconds": autoapprove,
            "LifetimeInSeconds": lifetime,
            "MaxAssignments": maxassignments}

        qualcounter = 0

        if minapprovedpercent:
            qualcounter += 1
            base = "QualificationRequirement.{0}." .format(qualcounter)
            r[base + "QualificationTypeId"] = "000000000000000000L0"
            r[base + "Comparator"] = "GreaterThanOrEqualTo"
            r[base + "IntegerValue"] = minapprovedpercent 

        if minapprovedamount:
            qualcounter += 1
            base = "QualificationRequirement.{0}." .format(qualcounter)
            r[base + "QualificationTypeId"] = "00000000000000000040"
            r[base + "Comparator"] = "GreaterThanOrEqualTo"
            r[base + "IntegerValue"] = minapprovedamount 

        if countrycode:
            qualcounter += 1
            base = "QualificationRequirement.{0}." .format(qualcounter)
            r[base + "QualificationTypeId"] = "00000000000000000071"
            r[base + "Comparator"] = "EqualTo"
            r[base + "LocaleValue.Country"] = countrycode 

        enc_page = page.replace("&", "&amp;")
        r["Question"] = ("<ExternalQuestion xmlns=\"http://mechanicalturk"
                         ".amazonaws.com/AWSMechanicalTurkDataSchemas/"
                         "2006-07-14/ExternalQuestion.xsd\">"
                         "<ExternalURL>{0}/{1}</ExternalURL>"
                         "<FrameHeight>{2}</FrameHeight>"
                         "</ExternalQuestion>").format(self.localhost,
                                                       enc_page, height)

        r = self.request("CreateHIT", r);
        r.validate("HIT/Request/IsValid", "HIT/Request/Errors/Error/Message")
        r.store("HIT/HITId", "hitid")
        r.store("HIT/HITTypeId", "hittypeid")
        return r
    
    def disable(self, hitid):
        """
        Disables the HIT from the MTurk service.
        """
        r = self.request("DisableHIT", {"HITId": hitid})
        r.validate("DisableHITResult/Request/IsValid",
                   "DisableHITResult/Request/Errors/Error/Message")
        return r

    def purge(self):
        """
        Disables all the HITs on the MTurk server. Useful for debugging.
        """
        while True:
            r = self.request("SearchHITs", {"SortProperty": "CreationTime",
                                            "SortDirection": "Descending",
                                            "PageSize": "100",
                                            "PageNumber": "1"})
            r.validate("SearchHITsResult/Request/IsValid")
            r.store("SearchHITsResult/TotalNumResults", "num", int)
            if r.num == 0:
                return
            for hit in r.tree.findall("SearchHITsResult/HIT"):
                hitid = hit.find("HITId").text.strip()
                try:
                    self.disable(hitid)
                except CommunicationError:
                    pass
            print "Next page"

    def accept(self, assignmentid, feedback = ""):
        """
        Accepts the assignment and pays the worker.
        """
        r = self.request("ApproveAssignment",
                         {"AssignmentId": assignmentid,
                          "RequesterFeedback": feedback})
        r.validate("ApproveAssignmentResult/Request/IsValid",
                   "ApproveAssignmentResult/Request/Errors/Error/Message")
        return r

    def reject(self, assignmentid, feedback = ""):
        """
        Rejects the assignment and does not pay the worker.
        """
        r = self.request("RejectAssignment",
                         {"AssignmentId": assignmentid,
                          "RequesterFeedback": feedback})
        r.validate("RejectAssignmentResult/Request/IsValid",
                   "RejectAssignmentResult/Request/Errors/Error/Message")
        return r

    def getassignments(self, hitid):
        """
        Gets all the assignments for a HIT.
        """
        r = self.request("GetAssignmentsForHIT",
                         {"HITId": hitid,
                          "PageSize": 100})
        r.validate("GetAssignmentsForHITResult/Request/IsValid", "")
        r.store("GetAssignmentsForHITResult/Assignment", "assignments", all = True)
        return r

    def bonus(self, workerid, assignmentid, amount, feedback = ""):
        """
        Grants a bonus to a worker for an assignment.
        """
        r = self.request("GrantBonus",
            {"WorkerId": workerid,
             "AssignmentId": assignmentid,
             "BonusAmount.1.Amount": amount,
             "BonusAmount.1.CurrencyCode": "USD",
             "Reason": feedback});
        r.validate("GrantBonusResult/Request/IsValid",
                   "GrantBonusResult/Request/Errors/Error/Message")
        return r

    def block(self, workerid, reason = ""):
        """
        Blocks the worker from working on any of our HITs.
        """
        r = self.request("BlockWorker", {"WorkerId": workerid,
                                         "Reason": reason})
        r.validate("BlockWorkerResult/Request/IsValid",
                   "BlockWorkerResult/Request/Errors/Error/Message")
        return r

    def unblock(self, workerid, reason = ""):
        """
        Unblocks the worker and allows him to work for us again.
        """
        r = self.request("UnblockWorker", {"WorkerId": workerid,
                                           "Reason": reason})
        r.validate("UnblockWorkerResult/Request/IsValid",
                   "UnblockWorkerResult/Request/Errors/Error/Message")
        return r

    def email(self, workerid, subject, message):
        """
        Sends an email to the worker.
        """
        r = self.request("NotifyWorkers", {"Subject": subject,
                                           "MessageText": message,
                                           "WorkerId.1": workerid})
        r.validate("NotifyWorkersResult/Request/IsValid",
                   "NotifyWorkersResult/Request/Errors/Error/Message")
        return r

    def getstatistic(self, statistic, type, timeperiod = "LifeToDate"):
        """
        Returns the total reward payout.
        """
        r = self.request("GetRequesterStatistic", {"Statistic": statistic,
                                                   "TimePeriod": timeperiod})
        r.validate("GetStatisticResult/Request/IsValid")
        xmlvalue = "LongValue" if type is int else "DoubleValue"
        r.store("GetStatisticResult/DataPoint/{0}".format(xmlvalue),
                "value", type)
        return r.value

    @property
    def balance(self):
        """
        Returns a response object with the available balance in the amount
        attribute.
        """
        r = self.request("GetAccountBalance")
        r.validate("GetAccountBalanceResult/Request/IsValid")
        r.store("GetAccountBalanceResult/AvailableBalance/Amount",
                "amount", float)
        r.store("GetAccountBalanceResult/AvailableBalance/CurrencyCode",
                "currency")
        return r.amount

    @property
    def rewardpayout(self):
        """
        Returns the total reward payout.
        """
        reward = self.getstatistic("TotalRewardPayout", float)
        bonus = self.getstatistic("TotalBonusPayout", float)
        return reward + bonus

    @property
    def approvalpercentage(self):
        """
        Returns the percent of assignments approved.
        """
        return self.getstatistic("PercentAssignmentsApproved", float)

    @property
    def feepayout(self):
        """
        Returns how much we paid to Amazon in fees.
        """
        reward = self.getstatistic("TotalRewardFeePayout", float)
        bonus = self.getstatistic("TotalBonusFeePayout", float)
        return reward + bonus

    @property
    def numcreated(self):
        """
        Returns the total number of HITs created.
        """
        return self.getstatistic("NumberHITsCreated", int)

class MTurkResponse(object):
    """
    A generic response from the MTurk server.
    """
    def __init__(self, operation, httpresponse):
        self.operation = operation
        self.httpresponse = httpresponse
        self.data = httpresponse.read()
        self.tree = ElementTree.fromstring(self.data)
        self.values = {}

    def validate(self, valid, errormessage = None):
        """
        Validates the response and raises an exception if invalid.
        
        Valid contains a path that must contain False if the response
        is invalid.
        
        If errormessage is not None, use this field as the error description.
        """
        valide = self.tree.find(valid)
        if valide is None:
            raise CommunicationError("XML malformed", self)
        elif valide.text.strip() == "False":
            if errormessage:
                errormessage = self.tree.find(errormessage)
                if errormessage is None:
                    raise CommunicationError("Response not valid "
                        "and XML malformed", self)
                raise CommunicationError(errormessage.text.strip(), self)
            else:
                raise CommunicationError("Response not valid", self)

    def store(self, path, name, type = str, all = False):
        """
        Stores the text at path into the attribute name.
        """
        if all:
            node = self.tree.findall(path)
            self.values[name] = node
        else:
            node = self.tree.find(path)
            if node is None:
                raise CommunicationError("XML malformed "
                    "(cannot find {0})".format(path), self)
            self.values[name] = type(node.text.strip())

    def __getattr__(self, name):
        """
        Used to lookup attributes.
        """
        if name not in self.values:
            raise AttributeError("{0} is not stored".format(name))
        return self.values[name]

class CommunicationError(Exception):
    """
    The error raised due to a communication failure with MTurk.
    """
    def __init__(self, error, response):
        self.error = error
        self.response = response

    def __str__(self):
        return self.error

if __name__ == "__main__":
    server = MTurkServer(MTURK_SIGNATURE, MTURK_ACCESSKEY, MTURK_HOST, MTURK_SANDBOX)

    if len(sys.argv) < 2:
        print "Error: missing command"
        raise SystemExit()

    command = sys.argv[1]
    arguments = sys.argv[2:]
    if command == "create":
        create(arguments) 
    elif command == "retrieve":
        retrieve(arguments)
    elif command == "disable":
        disable(arguments)
    elif command == "compensate":
        compensate(arguments)
    elif command == "status":
        status(arguments)
    else:
        print "Error: invalid command: {}".format(command)
