# PySNMP SMI module. Autogenerated from smidump -f python DNS-SERVER-MIB
# by libsmi2pysnmp-0.1.3 at Mon Apr  2 20:38:50 2012,
# Python version sys.version_info(major=2, minor=7, micro=2, releaselevel='final', serial=0)

# Imports

( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( ModuleCompliance, ObjectGroup, ) = mibBuilder.importSymbols("SNMPv2-CONF", "ModuleCompliance", "ObjectGroup")
( Bits, Counter32, Gauge32, Integer32, IpAddress, ModuleIdentity, MibIdentifier, ObjectIdentity, MibScalar, MibTable, MibTableRow, MibTableColumn, TimeTicks, mib_2, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Counter32", "Gauge32", "Integer32", "IpAddress", "ModuleIdentity", "MibIdentifier", "ObjectIdentity", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "TimeTicks", "mib-2")
( DisplayString, RowStatus, TextualConvention, TruthValue, ) = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "RowStatus", "TextualConvention", "TruthValue")

# Types

class DnsClass(TextualConvention, Integer32):
    displayHint = "d"
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(0,65535)
    
class DnsName(OctetString):
    subtypeSpec = OctetString.subtypeSpec+ValueSizeConstraint(0,255)
    
class DnsOpCode(Integer32):
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(0,15)
    
class DnsQClass(TextualConvention, Integer32):
    displayHint = "d"
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(0,65535)
    
class DnsQType(TextualConvention, Integer32):
    displayHint = "d"
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(0,65535)
    
class DnsRespCode(Integer32):
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(0,15)
    
class DnsType(TextualConvention, Integer32):
    displayHint = "d"
    subtypeSpec = Integer32.subtypeSpec+ValueRangeConstraint(0,65535)
    
class DnsNameAsIndex(DnsName):
    pass

class DnsTime(TextualConvention, Gauge32):
    displayHint = "d"
    

# Objects

dns = ObjectIdentity((1, 3, 6, 1, 2, 1, 32))
if mibBuilder.loadTexts: dns.setDescription("The OID assigned to DNS MIB work by the IANA.")
dnsServMIB = ModuleIdentity((1, 3, 6, 1, 2, 1, 32, 1)).setRevisions(("1994-01-28 22:51",))
if mibBuilder.loadTexts: dnsServMIB.setOrganization("IETF DNS Working Group")
if mibBuilder.loadTexts: dnsServMIB.setContactInfo("       Rob Austein\nPostal: Epilogue Technology Corporation\n        268 Main Street, Suite 283\n        North Reading, MA 10864\n        US\n   Tel: +1 617 245 0804\n   Fax: +1 617 245 8122\nE-Mail: sra@epilogue.com\n\n        Jon Saperia\nPostal: Digital Equipment Corporation\n        110 Spit Brook Road\n        ZKO1-3/H18\n        Nashua, NH 03062-2698\n        US\n   Tel: +1 603 881 0480\n   Fax: +1 603 881 0120\n Email: saperia@zko.dec.com")
if mibBuilder.loadTexts: dnsServMIB.setDescription("The MIB module for entities implementing the server side\nof the Domain Name System (DNS) protocol.")
dnsServMIBObjects = MibIdentifier((1, 3, 6, 1, 2, 1, 32, 1, 1))
dnsServConfig = MibIdentifier((1, 3, 6, 1, 2, 1, 32, 1, 1, 1))
dnsServConfigImplementIdent = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 1, 1), DisplayString()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServConfigImplementIdent.setDescription("The implementation identification string for the DNS\nserver software in use on the system, for example;\n`FNS-2.1'")
dnsServConfigRecurs = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 1, 2), Integer().subtype(subtypeSpec=SingleValueConstraint(1,2,3,)).subtype(namedValues=NamedValues(("available", 1), ("restricted", 2), ("unavailable", 3), ))).setMaxAccess("readwrite")
if mibBuilder.loadTexts: dnsServConfigRecurs.setDescription("This represents the recursion services offered by this\nname server.  The values that can be read or written\nare:\n\navailable(1) - performs recursion on requests from\nclients.\n\nrestricted(2) - recursion is performed on requests only\nfrom certain clients, for example; clients on an access\ncontrol list.\n\nunavailable(3) - recursion is not available.")
dnsServConfigUpTime = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 1, 3), DnsTime()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServConfigUpTime.setDescription("If the server has a persistent state (e.g., a process),\nthis value will be the time elapsed since it started.\nFor software without persistant state, this value will\nbe zero.")
dnsServConfigResetTime = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 1, 4), DnsTime()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServConfigResetTime.setDescription("If the server has a persistent state (e.g., a process)\nand supports a `reset' operation (e.g., can be told to\nre-read configuration files), this value will be the\ntime elapsed since the last time the name server was\n`reset.'  For software that does not have persistence or\ndoes not support a `reset' operation, this value will be\nzero.")
dnsServConfigReset = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 1, 5), Integer().subtype(subtypeSpec=SingleValueConstraint(2,3,4,1,)).subtype(namedValues=NamedValues(("other", 1), ("reset", 2), ("initializing", 3), ("running", 4), ))).setMaxAccess("readwrite")
if mibBuilder.loadTexts: dnsServConfigReset.setDescription("Status/action object to reinitialize any persistant name\nserver state.  When set to reset(2), any persistant\nname server state (such as a process) is reinitialized as\nif the name server had just been started.  This value\nwill never be returned by a read operation.  When read,\none of the following values will be returned:\n    other(1) - server in some unknown state;\n    initializing(3) - server (re)initializing;\n    running(4) - server currently running.")
dnsServCounter = MibIdentifier((1, 3, 6, 1, 2, 1, 32, 1, 1, 2))
dnsServCounterAuthAns = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 2), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterAuthAns.setDescription("Number of queries which were authoritatively answered.")
dnsServCounterAuthNoNames = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 3), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterAuthNoNames.setDescription("Number of queries for which `authoritative no such name'\nresponses were made.")
dnsServCounterAuthNoDataResps = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 4), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterAuthNoDataResps.setDescription("Number of queries for which `authoritative no such data'\n(empty answer) responses were made.")
dnsServCounterNonAuthDatas = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 5), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterNonAuthDatas.setDescription("Number of queries which were non-authoritatively\nanswered (cached data).")
dnsServCounterNonAuthNoDatas = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 6), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterNonAuthNoDatas.setDescription("Number of queries which were non-authoritatively\nanswered with no data (empty answer).")
dnsServCounterReferrals = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 7), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterReferrals.setDescription("Number of requests that were referred to other servers.")
dnsServCounterErrors = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 8), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterErrors.setDescription("Number of requests the server has processed that were\nanswered with errors (RCODE values other than 0 and 3).")
dnsServCounterRelNames = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 9), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterRelNames.setDescription("Number of requests received by the server for names that\nare only 1 label long (text form - no internal dots).")
dnsServCounterReqRefusals = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 10), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterReqRefusals.setDescription("Number of DNS requests refused by the server.")
dnsServCounterReqUnparses = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 11), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterReqUnparses.setDescription("Number of requests received which were unparseable.")
dnsServCounterOtherErrors = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 12), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterOtherErrors.setDescription("Number of requests which were aborted for other (local)\nserver errors.")
dnsServCounterTable = MibTable((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 13))
if mibBuilder.loadTexts: dnsServCounterTable.setDescription("Counter information broken down by DNS class and type.")
dnsServCounterEntry = MibTableRow((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 13, 1)).setIndexNames((0, "DNS-SERVER-MIB", "dnsServCounterOpCode"), (0, "DNS-SERVER-MIB", "dnsServCounterQClass"), (0, "DNS-SERVER-MIB", "dnsServCounterQType"), (0, "DNS-SERVER-MIB", "dnsServCounterTransport"))
if mibBuilder.loadTexts: dnsServCounterEntry.setDescription("This table contains count information for each DNS class\nand type value known to the server.  The index allows\nmanagement software to to create indices to the table to\nget the specific information desired, e.g., number of\nqueries over UDP for records with type value `A' which\ncame to this server.  In order to prevent an\nuncontrolled expansion of rows in the table; if\ndnsServCounterRequests is 0 and dnsServCounterResponses\nis 0, then the row does not exist and `no such' is\nreturned when the agent is queried for such instances.")
dnsServCounterOpCode = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 13, 1, 1), DnsOpCode()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: dnsServCounterOpCode.setDescription("The DNS OPCODE being counted in this row of the table.")
dnsServCounterQClass = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 13, 1, 2), DnsClass()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: dnsServCounterQClass.setDescription("The class of record being counted in this row of the\ntable.")
dnsServCounterQType = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 13, 1, 3), DnsType()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: dnsServCounterQType.setDescription("The type of record which is being counted in this row in\nthe table.")
dnsServCounterTransport = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 13, 1, 4), Integer().subtype(subtypeSpec=SingleValueConstraint(1,3,2,)).subtype(namedValues=NamedValues(("udp", 1), ("tcp", 2), ("other", 3), ))).setMaxAccess("noaccess")
if mibBuilder.loadTexts: dnsServCounterTransport.setDescription("A value of udp(1) indicates that the queries reported on\nthis row were sent using UDP.\n\nA value of tcp(2) indicates that the queries reported on\nthis row were sent using TCP.\n\nA value of other(3) indicates that the queries reported\non this row were sent using a transport that was neither\nTCP nor UDP.")
dnsServCounterRequests = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 13, 1, 5), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterRequests.setDescription("Number of requests (queries) that have been recorded in\nthis row of the table.")
dnsServCounterResponses = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 2, 13, 1, 6), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServCounterResponses.setDescription("Number of responses made by the server since\ninitialization for the kind of query identified on this\nrow of the table.")
dnsServOptCounter = MibIdentifier((1, 3, 6, 1, 2, 1, 32, 1, 1, 3))
dnsServOptCounterSelfAuthAns = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 1), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfAuthAns.setDescription("Number of requests the server has processed which\noriginated from a resolver on the same host for which\nthere has been an authoritative answer.")
dnsServOptCounterSelfAuthNoNames = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 2), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfAuthNoNames.setDescription("Number of requests the server has processed which\noriginated from a resolver on the same host for which\nthere has been an authoritative no such name answer\ngiven.")
dnsServOptCounterSelfAuthNoDataResps = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 3), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfAuthNoDataResps.setDescription("Number of requests the server has processed which\noriginated from a resolver on the same host for which\nthere has been an authoritative no such data answer\n(empty answer) made.")
dnsServOptCounterSelfNonAuthDatas = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 4), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfNonAuthDatas.setDescription("Number of requests the server has processed which\noriginated from a resolver on the same host for which a\nnon-authoritative answer (cached data) was made.")
dnsServOptCounterSelfNonAuthNoDatas = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 5), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfNonAuthNoDatas.setDescription("Number of requests the server has processed which\noriginated from a resolver on the same host for which a\n`non-authoritative, no such data' response was made\n(empty answer).")
dnsServOptCounterSelfReferrals = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 6), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfReferrals.setDescription("Number of queries the server has processed which\noriginated from a resolver on the same host and were\nreferred to other servers.")
dnsServOptCounterSelfErrors = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 7), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfErrors.setDescription("Number of requests the server has processed which\noriginated from a resolver on the same host which have\nbeen answered with errors (RCODEs other than 0 and 3).")
dnsServOptCounterSelfRelNames = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 8), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfRelNames.setDescription("Number of requests received for names that are only 1\nlabel long (text form - no internal dots) the server has\nprocessed which originated from a resolver on the same\nhost.")
dnsServOptCounterSelfReqRefusals = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 9), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfReqRefusals.setDescription("Number of DNS requests refused by the server which\noriginated from a resolver on the same host.")
dnsServOptCounterSelfReqUnparses = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 10), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfReqUnparses.setDescription("Number of requests received which were unparseable and\nwhich originated from a resolver on the same host.")
dnsServOptCounterSelfOtherErrors = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 11), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterSelfOtherErrors.setDescription("Number of requests which were aborted for other (local)\nserver errors and which originated on the same host.")
dnsServOptCounterFriendsAuthAns = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 12), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsAuthAns.setDescription("Number of queries originating from friends which were\nauthoritatively answered.  The definition of friends is\na locally defined matter.")
dnsServOptCounterFriendsAuthNoNames = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 13), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsAuthNoNames.setDescription("Number of queries originating from friends, for which\nauthoritative `no such name' responses were made.  The\ndefinition of friends is a locally defined matter.")
dnsServOptCounterFriendsAuthNoDataResps = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 14), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsAuthNoDataResps.setDescription("Number of queries originating from friends for which\nauthoritative no such data (empty answer) responses were\nmade.  The definition of friends is a locally defined\nmatter.")
dnsServOptCounterFriendsNonAuthDatas = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 15), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsNonAuthDatas.setDescription("Number of queries originating from friends which were\nnon-authoritatively answered (cached data). The\ndefinition of friends is a locally defined matter.")
dnsServOptCounterFriendsNonAuthNoDatas = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 16), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsNonAuthNoDatas.setDescription("Number of queries originating from friends which were\nnon-authoritatively answered with no such data (empty\nanswer).")
dnsServOptCounterFriendsReferrals = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 17), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsReferrals.setDescription("Number of requests which originated from friends that\nwere referred to other servers.  The definition of\nfriends is a locally defined matter.")
dnsServOptCounterFriendsErrors = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 18), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsErrors.setDescription("Number of requests the server has processed which\noriginated from friends and were answered with errors\n(RCODE values other than 0 and 3).  The definition of\nfriends is a locally defined matter.")
dnsServOptCounterFriendsRelNames = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 19), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsRelNames.setDescription("Number of requests received for names from friends that\nare only 1 label long (text form - no internal dots) the\nserver has processed.")
dnsServOptCounterFriendsReqRefusals = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 20), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsReqRefusals.setDescription("Number of DNS requests refused by the server which were\nreceived from `friends'.")
dnsServOptCounterFriendsReqUnparses = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 21), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsReqUnparses.setDescription("Number of requests received which were unparseable and\nwhich originated from `friends'.")
dnsServOptCounterFriendsOtherErrors = MibScalar((1, 3, 6, 1, 2, 1, 32, 1, 1, 3, 22), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServOptCounterFriendsOtherErrors.setDescription("Number of requests which were aborted for other (local)\nserver errors and which originated from `friends'.")
dnsServZone = MibIdentifier((1, 3, 6, 1, 2, 1, 32, 1, 1, 4))
dnsServZoneTable = MibTable((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1))
if mibBuilder.loadTexts: dnsServZoneTable.setDescription("Table of zones for which this name server provides\ninformation.  Each of the zones may be loaded from stable\nstorage via an implementation-specific mechanism or may\nbe obtained from another name server via a zone transfer.\n\nIf name server doesn't load any zones, this table is\nempty.")
dnsServZoneEntry = MibTableRow((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1, 1)).setIndexNames((0, "DNS-SERVER-MIB", "dnsServZoneName"), (0, "DNS-SERVER-MIB", "dnsServZoneClass"))
if mibBuilder.loadTexts: dnsServZoneEntry.setDescription("An entry in the name server zone table.  New rows may be\nadded either via SNMP or by the name server itself.")
dnsServZoneName = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1, 1, 1), DnsNameAsIndex()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: dnsServZoneName.setDescription("DNS name of the zone described by this row of the table.\nThis is the owner name of the SOA RR that defines the\ntop of the zone. This is name is in uppercase:\ncharacters 'a' through 'z' are mapped to 'A' through 'Z'\nin order to make the lexical ordering useful.")
dnsServZoneClass = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1, 1, 2), DnsClass()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: dnsServZoneClass.setDescription("DNS class of the RRs in this zone.")
dnsServZoneLastReloadSuccess = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1, 1, 3), DnsTime()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServZoneLastReloadSuccess.setDescription("Elapsed time in seconds since last successful reload of\nthis zone.")
dnsServZoneLastReloadAttempt = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1, 1, 4), DnsTime()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServZoneLastReloadAttempt.setDescription("Elapsed time in seconds since last attempted reload of\nthis zone.")
dnsServZoneLastSourceAttempt = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1, 1, 5), IpAddress()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServZoneLastSourceAttempt.setDescription("IP address of host from which most recent zone transfer\nof this zone was attempted.  This value should match the\nvalue of dnsServZoneSourceSuccess if the attempt was\nsucccessful.  If zone transfer has not been attempted\nwithin the memory of this name server, this value should\nbe 0.0.0.0.")
dnsServZoneStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1, 1, 6), RowStatus()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: dnsServZoneStatus.setDescription("The status of the information represented in this row of\nthe table.")
dnsServZoneSerial = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1, 1, 7), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServZoneSerial.setDescription("Zone serial number (from the SOA RR) of the zone\nrepresented by this row of the table.  If the zone has\nnot been successfully loaded within the memory of this\nname server, the value of this variable is zero.")
dnsServZoneCurrent = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1, 1, 8), TruthValue()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServZoneCurrent.setDescription("Whether the server's copy of the zone represented by\nthis row of the table is currently valid.  If the zone\nhas never been successfully loaded or has expired since\nit was last succesfully loaded, this variable will have\nthe value false(2), otherwise this variable will have\nthe value true(1).")
dnsServZoneLastSourceSuccess = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 1, 1, 9), IpAddress()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dnsServZoneLastSourceSuccess.setDescription("IP address of host which was the source of the most\nrecent successful zone transfer for this zone.  If\nunknown (e.g., zone has never been successfully\ntransfered) or irrelevant (e.g., zone was loaded from\nstable storage), this value should be 0.0.0.0.")
dnsServZoneSrcTable = MibTable((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 2))
if mibBuilder.loadTexts: dnsServZoneSrcTable.setDescription("This table is a list of IP addresses from which the\nserver will attempt to load zone information using DNS\nzone transfer operations.  A reload may occur due to SNMP\noperations that create a row in dnsServZoneTable or a\nSET to object dnsServZoneReload.  This table is only\nused when the zone is loaded via zone transfer.")
dnsServZoneSrcEntry = MibTableRow((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 2, 1)).setIndexNames((0, "DNS-SERVER-MIB", "dnsServZoneSrcName"), (0, "DNS-SERVER-MIB", "dnsServZoneSrcClass"), (0, "DNS-SERVER-MIB", "dnsServZoneSrcAddr"))
if mibBuilder.loadTexts: dnsServZoneSrcEntry.setDescription("An entry in the name server zone source table.")
dnsServZoneSrcName = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 2, 1, 1), DnsNameAsIndex()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: dnsServZoneSrcName.setDescription("DNS name of the zone to which this entry applies.")
dnsServZoneSrcClass = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 2, 1, 2), DnsClass()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: dnsServZoneSrcClass.setDescription("DNS class of zone to which this entry applies.")
dnsServZoneSrcAddr = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 2, 1, 3), IpAddress()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: dnsServZoneSrcAddr.setDescription("IP address of name server host from which this zone\nmight be obtainable.")
dnsServZoneSrcStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 32, 1, 1, 4, 2, 1, 4), RowStatus()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: dnsServZoneSrcStatus.setDescription("The status of the information represented in this row of\nthe table.")
dnsServMIBGroups = MibIdentifier((1, 3, 6, 1, 2, 1, 32, 1, 2))
dnsServMIBCompliances = MibIdentifier((1, 3, 6, 1, 2, 1, 32, 1, 3))

# Augmentions

# Groups

dnsServConfigGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 32, 1, 2, 1)).setObjects(*(("DNS-SERVER-MIB", "dnsServConfigUpTime"), ("DNS-SERVER-MIB", "dnsServConfigRecurs"), ("DNS-SERVER-MIB", "dnsServConfigImplementIdent"), ("DNS-SERVER-MIB", "dnsServConfigResetTime"), ("DNS-SERVER-MIB", "dnsServConfigReset"), ) )
if mibBuilder.loadTexts: dnsServConfigGroup.setDescription("A collection of objects providing basic configuration\ncontrol of a DNS name server.")
dnsServCounterGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 32, 1, 2, 2)).setObjects(*(("DNS-SERVER-MIB", "dnsServCounterReqRefusals"), ("DNS-SERVER-MIB", "dnsServCounterReqUnparses"), ("DNS-SERVER-MIB", "dnsServCounterAuthNoNames"), ("DNS-SERVER-MIB", "dnsServCounterQType"), ("DNS-SERVER-MIB", "dnsServCounterQClass"), ("DNS-SERVER-MIB", "dnsServCounterTransport"), ("DNS-SERVER-MIB", "dnsServCounterErrors"), ("DNS-SERVER-MIB", "dnsServCounterRequests"), ("DNS-SERVER-MIB", "dnsServCounterOpCode"), ("DNS-SERVER-MIB", "dnsServCounterAuthAns"), ("DNS-SERVER-MIB", "dnsServCounterReferrals"), ("DNS-SERVER-MIB", "dnsServCounterResponses"), ("DNS-SERVER-MIB", "dnsServCounterNonAuthNoDatas"), ("DNS-SERVER-MIB", "dnsServCounterOtherErrors"), ("DNS-SERVER-MIB", "dnsServCounterAuthNoDataResps"), ("DNS-SERVER-MIB", "dnsServCounterRelNames"), ("DNS-SERVER-MIB", "dnsServCounterNonAuthDatas"), ) )
if mibBuilder.loadTexts: dnsServCounterGroup.setDescription("A collection of objects providing basic instrumentation\nof a DNS name server.")
dnsServOptCounterGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 32, 1, 2, 3)).setObjects(*(("DNS-SERVER-MIB", "dnsServOptCounterSelfReqRefusals"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsErrors"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsReqRefusals"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsReqUnparses"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsAuthNoDataResps"), ("DNS-SERVER-MIB", "dnsServOptCounterSelfErrors"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsNonAuthNoDatas"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsNonAuthDatas"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsRelNames"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsOtherErrors"), ("DNS-SERVER-MIB", "dnsServOptCounterSelfReferrals"), ("DNS-SERVER-MIB", "dnsServOptCounterSelfAuthAns"), ("DNS-SERVER-MIB", "dnsServOptCounterSelfNonAuthNoDatas"), ("DNS-SERVER-MIB", "dnsServOptCounterSelfReqUnparses"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsAuthAns"), ("DNS-SERVER-MIB", "dnsServOptCounterSelfAuthNoDataResps"), ("DNS-SERVER-MIB", "dnsServOptCounterSelfOtherErrors"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsAuthNoNames"), ("DNS-SERVER-MIB", "dnsServOptCounterSelfRelNames"), ("DNS-SERVER-MIB", "dnsServOptCounterSelfNonAuthDatas"), ("DNS-SERVER-MIB", "dnsServOptCounterSelfAuthNoNames"), ("DNS-SERVER-MIB", "dnsServOptCounterFriendsReferrals"), ) )
if mibBuilder.loadTexts: dnsServOptCounterGroup.setDescription("A collection of objects providing extended\ninstrumentation of a DNS name server.")
dnsServZoneGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 32, 1, 2, 4)).setObjects(*(("DNS-SERVER-MIB", "dnsServZoneCurrent"), ("DNS-SERVER-MIB", "dnsServZoneName"), ("DNS-SERVER-MIB", "dnsServZoneSerial"), ("DNS-SERVER-MIB", "dnsServZoneStatus"), ("DNS-SERVER-MIB", "dnsServZoneClass"), ("DNS-SERVER-MIB", "dnsServZoneSrcStatus"), ("DNS-SERVER-MIB", "dnsServZoneLastSourceSuccess"), ("DNS-SERVER-MIB", "dnsServZoneLastReloadAttempt"), ("DNS-SERVER-MIB", "dnsServZoneLastReloadSuccess"), ("DNS-SERVER-MIB", "dnsServZoneSrcClass"), ("DNS-SERVER-MIB", "dnsServZoneSrcName"), ("DNS-SERVER-MIB", "dnsServZoneSrcAddr"), ("DNS-SERVER-MIB", "dnsServZoneLastSourceAttempt"), ) )
if mibBuilder.loadTexts: dnsServZoneGroup.setDescription("A collection of objects providing configuration control\nof a DNS name server which loads authoritative zones.")

# Compliances

dnsServMIBCompliance = ModuleCompliance((1, 3, 6, 1, 2, 1, 32, 1, 3, 1)).setObjects(*(("DNS-SERVER-MIB", "dnsServCounterGroup"), ("DNS-SERVER-MIB", "dnsServZoneGroup"), ("DNS-SERVER-MIB", "dnsServConfigGroup"), ("DNS-SERVER-MIB", "dnsServOptCounterGroup"), ) )
if mibBuilder.loadTexts: dnsServMIBCompliance.setDescription("The compliance statement for agents implementing the DNS\nname server MIB extensions.")

# Exports

# Module identity
mibBuilder.exportSymbols("DNS-SERVER-MIB", PYSNMP_MODULE_ID=dnsServMIB)

# Types
mibBuilder.exportSymbols("DNS-SERVER-MIB", DnsClass=DnsClass, DnsName=DnsName, DnsOpCode=DnsOpCode, DnsQClass=DnsQClass, DnsQType=DnsQType, DnsRespCode=DnsRespCode, DnsType=DnsType, DnsNameAsIndex=DnsNameAsIndex, DnsTime=DnsTime)

# Objects
mibBuilder.exportSymbols("DNS-SERVER-MIB", dns=dns, dnsServMIB=dnsServMIB, dnsServMIBObjects=dnsServMIBObjects, dnsServConfig=dnsServConfig, dnsServConfigImplementIdent=dnsServConfigImplementIdent, dnsServConfigRecurs=dnsServConfigRecurs, dnsServConfigUpTime=dnsServConfigUpTime, dnsServConfigResetTime=dnsServConfigResetTime, dnsServConfigReset=dnsServConfigReset, dnsServCounter=dnsServCounter, dnsServCounterAuthAns=dnsServCounterAuthAns, dnsServCounterAuthNoNames=dnsServCounterAuthNoNames, dnsServCounterAuthNoDataResps=dnsServCounterAuthNoDataResps, dnsServCounterNonAuthDatas=dnsServCounterNonAuthDatas, dnsServCounterNonAuthNoDatas=dnsServCounterNonAuthNoDatas, dnsServCounterReferrals=dnsServCounterReferrals, dnsServCounterErrors=dnsServCounterErrors, dnsServCounterRelNames=dnsServCounterRelNames, dnsServCounterReqRefusals=dnsServCounterReqRefusals, dnsServCounterReqUnparses=dnsServCounterReqUnparses, dnsServCounterOtherErrors=dnsServCounterOtherErrors, dnsServCounterTable=dnsServCounterTable, dnsServCounterEntry=dnsServCounterEntry, dnsServCounterOpCode=dnsServCounterOpCode, dnsServCounterQClass=dnsServCounterQClass, dnsServCounterQType=dnsServCounterQType, dnsServCounterTransport=dnsServCounterTransport, dnsServCounterRequests=dnsServCounterRequests, dnsServCounterResponses=dnsServCounterResponses, dnsServOptCounter=dnsServOptCounter, dnsServOptCounterSelfAuthAns=dnsServOptCounterSelfAuthAns, dnsServOptCounterSelfAuthNoNames=dnsServOptCounterSelfAuthNoNames, dnsServOptCounterSelfAuthNoDataResps=dnsServOptCounterSelfAuthNoDataResps, dnsServOptCounterSelfNonAuthDatas=dnsServOptCounterSelfNonAuthDatas, dnsServOptCounterSelfNonAuthNoDatas=dnsServOptCounterSelfNonAuthNoDatas, dnsServOptCounterSelfReferrals=dnsServOptCounterSelfReferrals, dnsServOptCounterSelfErrors=dnsServOptCounterSelfErrors, dnsServOptCounterSelfRelNames=dnsServOptCounterSelfRelNames, dnsServOptCounterSelfReqRefusals=dnsServOptCounterSelfReqRefusals, dnsServOptCounterSelfReqUnparses=dnsServOptCounterSelfReqUnparses, dnsServOptCounterSelfOtherErrors=dnsServOptCounterSelfOtherErrors, dnsServOptCounterFriendsAuthAns=dnsServOptCounterFriendsAuthAns, dnsServOptCounterFriendsAuthNoNames=dnsServOptCounterFriendsAuthNoNames, dnsServOptCounterFriendsAuthNoDataResps=dnsServOptCounterFriendsAuthNoDataResps, dnsServOptCounterFriendsNonAuthDatas=dnsServOptCounterFriendsNonAuthDatas, dnsServOptCounterFriendsNonAuthNoDatas=dnsServOptCounterFriendsNonAuthNoDatas, dnsServOptCounterFriendsReferrals=dnsServOptCounterFriendsReferrals, dnsServOptCounterFriendsErrors=dnsServOptCounterFriendsErrors, dnsServOptCounterFriendsRelNames=dnsServOptCounterFriendsRelNames, dnsServOptCounterFriendsReqRefusals=dnsServOptCounterFriendsReqRefusals, dnsServOptCounterFriendsReqUnparses=dnsServOptCounterFriendsReqUnparses, dnsServOptCounterFriendsOtherErrors=dnsServOptCounterFriendsOtherErrors, dnsServZone=dnsServZone, dnsServZoneTable=dnsServZoneTable, dnsServZoneEntry=dnsServZoneEntry, dnsServZoneName=dnsServZoneName, dnsServZoneClass=dnsServZoneClass, dnsServZoneLastReloadSuccess=dnsServZoneLastReloadSuccess, dnsServZoneLastReloadAttempt=dnsServZoneLastReloadAttempt, dnsServZoneLastSourceAttempt=dnsServZoneLastSourceAttempt, dnsServZoneStatus=dnsServZoneStatus, dnsServZoneSerial=dnsServZoneSerial, dnsServZoneCurrent=dnsServZoneCurrent, dnsServZoneLastSourceSuccess=dnsServZoneLastSourceSuccess, dnsServZoneSrcTable=dnsServZoneSrcTable, dnsServZoneSrcEntry=dnsServZoneSrcEntry, dnsServZoneSrcName=dnsServZoneSrcName, dnsServZoneSrcClass=dnsServZoneSrcClass, dnsServZoneSrcAddr=dnsServZoneSrcAddr, dnsServZoneSrcStatus=dnsServZoneSrcStatus, dnsServMIBGroups=dnsServMIBGroups, dnsServMIBCompliances=dnsServMIBCompliances)

# Groups
mibBuilder.exportSymbols("DNS-SERVER-MIB", dnsServConfigGroup=dnsServConfigGroup, dnsServCounterGroup=dnsServCounterGroup, dnsServOptCounterGroup=dnsServOptCounterGroup, dnsServZoneGroup=dnsServZoneGroup)

# Compliances
mibBuilder.exportSymbols("DNS-SERVER-MIB", dnsServMIBCompliance=dnsServMIBCompliance)