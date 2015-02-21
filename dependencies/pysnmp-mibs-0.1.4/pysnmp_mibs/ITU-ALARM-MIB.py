# PySNMP SMI module. Autogenerated from smidump -f python ITU-ALARM-MIB
# by libsmi2pysnmp-0.1.3 at Mon Apr  2 20:39:15 2012,
# Python version sys.version_info(major=2, minor=7, micro=2, releaselevel='final', serial=0)

# Imports

( alarmActiveDateAndTime, alarmActiveIndex, alarmListName, alarmModelIndex, ) = mibBuilder.importSymbols("ALARM-MIB", "alarmActiveDateAndTime", "alarmActiveIndex", "alarmListName", "alarmModelIndex")
( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( IANAItuEventType, IANAItuProbableCause, ) = mibBuilder.importSymbols("IANA-ITU-ALARM-TC-MIB", "IANAItuEventType", "IANAItuProbableCause")
( ItuPerceivedSeverity, ItuTrendIndication, ) = mibBuilder.importSymbols("ITU-ALARM-TC-MIB", "ItuPerceivedSeverity", "ItuTrendIndication")
( ZeroBasedCounter32, ) = mibBuilder.importSymbols("RMON2-MIB", "ZeroBasedCounter32")
( SnmpAdminString, ) = mibBuilder.importSymbols("SNMP-FRAMEWORK-MIB", "SnmpAdminString")
( ModuleCompliance, ObjectGroup, ) = mibBuilder.importSymbols("SNMPv2-CONF", "ModuleCompliance", "ObjectGroup")
( Bits, Gauge32, Integer32, ModuleIdentity, MibIdentifier, MibScalar, MibTable, MibTableRow, MibTableColumn, TimeTicks, mib_2, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Gauge32", "Integer32", "ModuleIdentity", "MibIdentifier", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "TimeTicks", "mib-2")
( AutonomousType, RowPointer, ) = mibBuilder.importSymbols("SNMPv2-TC", "AutonomousType", "RowPointer")

# Objects

ituAlarmMIB = ModuleIdentity((1, 3, 6, 1, 2, 1, 121)).setRevisions(("2004-09-09 00:00",))
if mibBuilder.loadTexts: ituAlarmMIB.setOrganization("IETF Distributed Management Working Group")
if mibBuilder.loadTexts: ituAlarmMIB.setContactInfo("WG EMail: disman@ietf.org\nSubscribe: disman-request@ietf.org\nhttp://www.ietf.org/html.charters/disman-charter.html\n\nChair:     Randy Presuhn\n           randy_presuhn@mindspring.com\n\nEditors:   Sharon Chisholm\n           Nortel Networks\n           PO Box 3511 Station C\n           Ottawa, Ont.  K1Y 4H7\n           Canada\n           schishol@nortelnetworks.com\n\n           Dan Romascanu\n           Avaya\n           Atidim Technology Park, Bldg. #3\n           Tel Aviv, 61131\n\n\n           Israel\n           Tel: +972-3-645-8414\n           Email: dromasca@avaya.com")
if mibBuilder.loadTexts: ituAlarmMIB.setDescription("The MIB module describes ITU Alarm information\nas defined in ITU Recommendation M.3100 [M.3100],\nX.733 [X.733] and X.736 [X.736].\n\nCopyright (C) The Internet Society (2004).  The\ninitial version of this MIB module was published\nin RFC 3877.  For full legal notices see the RFC\nitself.  Supplementary information may be available on:\nhttp://www.ietf.org/copyrights/ianamib.html")
ituAlarmObjects = MibIdentifier((1, 3, 6, 1, 2, 1, 121, 1))
ituAlarmModel = MibIdentifier((1, 3, 6, 1, 2, 1, 121, 1, 1))
ituAlarmTable = MibTable((1, 3, 6, 1, 2, 1, 121, 1, 1, 1))
if mibBuilder.loadTexts: ituAlarmTable.setDescription("A table of ITU Alarm information for possible alarms\non the system.")
ituAlarmEntry = MibTableRow((1, 3, 6, 1, 2, 1, 121, 1, 1, 1, 1)).setIndexNames((0, "ALARM-MIB", "alarmListName"), (0, "ALARM-MIB", "alarmModelIndex"), (0, "ITU-ALARM-MIB", "ituAlarmPerceivedSeverity"))
if mibBuilder.loadTexts: ituAlarmEntry.setDescription("Entries appear in this table whenever an entry is created\nin the alarmModelTable with a value of alarmModelState in\nthe range from 1 to 6.  Entries disappear from this table\nwhenever the corresponding entries are deleted from the\nalarmModelTable, including in cases where those entries\nhave been deleted due to local system action.  The value of\nalarmModelSpecificPointer has no effect on the creation\nor deletion of entries in this table.  Values of\nalarmModelState map to values of ituAlarmPerceivedSeverity\nas follows:\n\n\n  alarmModelState -> ituAlarmPerceivedSeverity\n         1        ->         clear (1)\n         2        ->         indeterminate (2)\n         3        ->         warning (6)\n         4        ->         minor (5)\n         5        ->         major (4)\n         6        ->         critical (3)\n\nAll other values of alarmModelState MUST NOT appear\nin this table.\n\nThis table MUST be persistent across system reboots.")
ituAlarmPerceivedSeverity = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 1, 1, 1, 1), ItuPerceivedSeverity()).setMaxAccess("noaccess")
if mibBuilder.loadTexts: ituAlarmPerceivedSeverity.setDescription("ITU perceived severity values.")
ituAlarmEventType = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 1, 1, 1, 2), IANAItuEventType()).setMaxAccess("readwrite")
if mibBuilder.loadTexts: ituAlarmEventType.setDescription("Represents the event type values for the alarms")
ituAlarmProbableCause = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 1, 1, 1, 3), IANAItuProbableCause()).setMaxAccess("readwrite")
if mibBuilder.loadTexts: ituAlarmProbableCause.setDescription("ITU probable cause values.")
ituAlarmAdditionalText = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 1, 1, 1, 4), SnmpAdminString()).setMaxAccess("readwrite")
if mibBuilder.loadTexts: ituAlarmAdditionalText.setDescription("Represents the additional text field for the alarm.")
ituAlarmGenericModel = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 1, 1, 1, 5), RowPointer()).setMaxAccess("readwrite")
if mibBuilder.loadTexts: ituAlarmGenericModel.setDescription("This object points to the corresponding\nrow in the alarmModelTable for this alarm severity.\n\nThis corresponding entry to alarmModelTable could also\nbe derived by performing the reverse of the mapping\nfrom alarmModelState to ituAlarmPerceivedSeverity defined\n\n\nin the description of ituAlarmEntry to determine the\nappropriate { alarmListName, alarmModelIndex, alarmModelState }\nfor this { alarmListName, alarmModelIndex,\nituAlarmPerceivedSeverity }.")
ituAlarmActive = MibIdentifier((1, 3, 6, 1, 2, 1, 121, 1, 2))
ituAlarmActiveTable = MibTable((1, 3, 6, 1, 2, 1, 121, 1, 2, 1))
if mibBuilder.loadTexts: ituAlarmActiveTable.setDescription("A table of ITU information for active alarms entries.")
ituAlarmActiveEntry = MibTableRow((1, 3, 6, 1, 2, 1, 121, 1, 2, 1, 1)).setIndexNames((0, "ALARM-MIB", "alarmListName"), (0, "ALARM-MIB", "alarmActiveDateAndTime"), (0, "ALARM-MIB", "alarmActiveIndex"))
if mibBuilder.loadTexts: ituAlarmActiveEntry.setDescription("Entries appear in this table when alarms are active.  They\nare removed when the alarm is no longer occurring.")
ituAlarmActiveTrendIndication = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 1, 1, 1), ItuTrendIndication()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveTrendIndication.setDescription("Represents the trend indication values for the alarms.")
ituAlarmActiveDetector = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 1, 1, 2), AutonomousType()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveDetector.setDescription("Represents the SecurityAlarmDetector object.")
ituAlarmActiveServiceProvider = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 1, 1, 3), AutonomousType()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveServiceProvider.setDescription("Represents the ServiceProvider object.")
ituAlarmActiveServiceUser = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 1, 1, 4), AutonomousType()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveServiceUser.setDescription("Represents the ServiceUser object.")
ituAlarmActiveStatsTable = MibTable((1, 3, 6, 1, 2, 1, 121, 1, 2, 2))
if mibBuilder.loadTexts: ituAlarmActiveStatsTable.setDescription("This table represents the ITU alarm statistics\ninformation.")
ituAlarmActiveStatsEntry = MibTableRow((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1)).setIndexNames((0, "ALARM-MIB", "alarmListName"))
if mibBuilder.loadTexts: ituAlarmActiveStatsEntry.setDescription("Statistics on the current active ITU alarms.")
ituAlarmActiveStatsIndeterminateCurrent = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1, 1), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveStatsIndeterminateCurrent.setDescription("A count of the current number of active alarms with a\nituAlarmPerceivedSeverity of indeterminate.")
ituAlarmActiveStatsCriticalCurrent = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1, 2), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveStatsCriticalCurrent.setDescription("A count of the current number of active alarms with a\nituAlarmPerceivedSeverity of critical.")
ituAlarmActiveStatsMajorCurrent = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1, 3), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveStatsMajorCurrent.setDescription("A count of the current number of active alarms with a\n\n\nituAlarmPerceivedSeverity of major.")
ituAlarmActiveStatsMinorCurrent = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1, 4), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveStatsMinorCurrent.setDescription("A count of the current number of active alarms with a\nituAlarmPerceivedSeverity of minor.")
ituAlarmActiveStatsWarningCurrent = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1, 5), Gauge32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveStatsWarningCurrent.setDescription("A count of the current number of active alarms with a\nituAlarmPerceivedSeverity of warning.")
ituAlarmActiveStatsIndeterminates = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1, 6), ZeroBasedCounter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveStatsIndeterminates.setDescription("A count of the total number of active alarms with a\nituAlarmPerceivedSeverity of indeterminate since system\nrestart.")
ituAlarmActiveStatsCriticals = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1, 7), ZeroBasedCounter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveStatsCriticals.setDescription("A count of the total number of active alarms with a\nituAlarmPerceivedSeverity of critical since system restart.")
ituAlarmActiveStatsMajors = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1, 8), ZeroBasedCounter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveStatsMajors.setDescription("A count of the total number of active alarms with a\nituAlarmPerceivedSeverity of major since system restart.")
ituAlarmActiveStatsMinors = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1, 9), ZeroBasedCounter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveStatsMinors.setDescription("A count of the total number of active alarms with a\nituAlarmPerceivedSeverity of minor since system restart.")
ituAlarmActiveStatsWarnings = MibTableColumn((1, 3, 6, 1, 2, 1, 121, 1, 2, 2, 1, 10), ZeroBasedCounter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: ituAlarmActiveStatsWarnings.setDescription("A count of the total number of active alarms with a\nituAlarmPerceivedSeverity of warning since system restart.")
ituAlarmConformance = MibIdentifier((1, 3, 6, 1, 2, 1, 121, 2))
ituAlarmCompliances = MibIdentifier((1, 3, 6, 1, 2, 1, 121, 2, 1))
ituAlarmGroups = MibIdentifier((1, 3, 6, 1, 2, 1, 121, 2, 2))

# Augmentions

# Groups

ituAlarmGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 121, 2, 2, 1)).setObjects(*(("ITU-ALARM-MIB", "ituAlarmGenericModel"), ("ITU-ALARM-MIB", "ituAlarmEventType"), ("ITU-ALARM-MIB", "ituAlarmProbableCause"), ) )
if mibBuilder.loadTexts: ituAlarmGroup.setDescription("ITU alarm details list group.")
ituAlarmServiceUserGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 121, 2, 2, 2)).setObjects(*(("ITU-ALARM-MIB", "ituAlarmActiveTrendIndication"), ("ITU-ALARM-MIB", "ituAlarmAdditionalText"), ) )
if mibBuilder.loadTexts: ituAlarmServiceUserGroup.setDescription("The use of these parameters is a service-user option.")
ituAlarmSecurityGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 121, 2, 2, 3)).setObjects(*(("ITU-ALARM-MIB", "ituAlarmActiveServiceProvider"), ("ITU-ALARM-MIB", "ituAlarmActiveDetector"), ("ITU-ALARM-MIB", "ituAlarmActiveServiceUser"), ) )
if mibBuilder.loadTexts: ituAlarmSecurityGroup.setDescription("Security Alarm Reporting Function")
ituAlarmStatisticsGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 121, 2, 2, 4)).setObjects(*(("ITU-ALARM-MIB", "ituAlarmActiveStatsCriticals"), ("ITU-ALARM-MIB", "ituAlarmActiveStatsIndeterminateCurrent"), ("ITU-ALARM-MIB", "ituAlarmActiveStatsCriticalCurrent"), ("ITU-ALARM-MIB", "ituAlarmActiveStatsMinorCurrent"), ("ITU-ALARM-MIB", "ituAlarmActiveStatsWarnings"), ("ITU-ALARM-MIB", "ituAlarmActiveStatsMinors"), ("ITU-ALARM-MIB", "ituAlarmActiveStatsMajorCurrent"), ("ITU-ALARM-MIB", "ituAlarmActiveStatsWarningCurrent"), ("ITU-ALARM-MIB", "ituAlarmActiveStatsMajors"), ("ITU-ALARM-MIB", "ituAlarmActiveStatsIndeterminates"), ) )
if mibBuilder.loadTexts: ituAlarmStatisticsGroup.setDescription("ITU Active Alarm Statistics.")

# Compliances

ituAlarmCompliance = ModuleCompliance((1, 3, 6, 1, 2, 1, 121, 2, 1, 1)).setObjects(*(("ITU-ALARM-MIB", "ituAlarmStatisticsGroup"), ("ITU-ALARM-MIB", "ituAlarmGroup"), ("ITU-ALARM-MIB", "ituAlarmServiceUserGroup"), ("ITU-ALARM-MIB", "ituAlarmSecurityGroup"), ) )
if mibBuilder.loadTexts: ituAlarmCompliance.setDescription("The compliance statement for systems supporting\nthe ITU Alarm MIB.")

# Exports

# Module identity
mibBuilder.exportSymbols("ITU-ALARM-MIB", PYSNMP_MODULE_ID=ituAlarmMIB)

# Objects
mibBuilder.exportSymbols("ITU-ALARM-MIB", ituAlarmMIB=ituAlarmMIB, ituAlarmObjects=ituAlarmObjects, ituAlarmModel=ituAlarmModel, ituAlarmTable=ituAlarmTable, ituAlarmEntry=ituAlarmEntry, ituAlarmPerceivedSeverity=ituAlarmPerceivedSeverity, ituAlarmEventType=ituAlarmEventType, ituAlarmProbableCause=ituAlarmProbableCause, ituAlarmAdditionalText=ituAlarmAdditionalText, ituAlarmGenericModel=ituAlarmGenericModel, ituAlarmActive=ituAlarmActive, ituAlarmActiveTable=ituAlarmActiveTable, ituAlarmActiveEntry=ituAlarmActiveEntry, ituAlarmActiveTrendIndication=ituAlarmActiveTrendIndication, ituAlarmActiveDetector=ituAlarmActiveDetector, ituAlarmActiveServiceProvider=ituAlarmActiveServiceProvider, ituAlarmActiveServiceUser=ituAlarmActiveServiceUser, ituAlarmActiveStatsTable=ituAlarmActiveStatsTable, ituAlarmActiveStatsEntry=ituAlarmActiveStatsEntry, ituAlarmActiveStatsIndeterminateCurrent=ituAlarmActiveStatsIndeterminateCurrent, ituAlarmActiveStatsCriticalCurrent=ituAlarmActiveStatsCriticalCurrent, ituAlarmActiveStatsMajorCurrent=ituAlarmActiveStatsMajorCurrent, ituAlarmActiveStatsMinorCurrent=ituAlarmActiveStatsMinorCurrent, ituAlarmActiveStatsWarningCurrent=ituAlarmActiveStatsWarningCurrent, ituAlarmActiveStatsIndeterminates=ituAlarmActiveStatsIndeterminates, ituAlarmActiveStatsCriticals=ituAlarmActiveStatsCriticals, ituAlarmActiveStatsMajors=ituAlarmActiveStatsMajors, ituAlarmActiveStatsMinors=ituAlarmActiveStatsMinors, ituAlarmActiveStatsWarnings=ituAlarmActiveStatsWarnings, ituAlarmConformance=ituAlarmConformance, ituAlarmCompliances=ituAlarmCompliances, ituAlarmGroups=ituAlarmGroups)

# Groups
mibBuilder.exportSymbols("ITU-ALARM-MIB", ituAlarmGroup=ituAlarmGroup, ituAlarmServiceUserGroup=ituAlarmServiceUserGroup, ituAlarmSecurityGroup=ituAlarmSecurityGroup, ituAlarmStatisticsGroup=ituAlarmStatisticsGroup)

# Compliances
mibBuilder.exportSymbols("ITU-ALARM-MIB", ituAlarmCompliance=ituAlarmCompliance)
