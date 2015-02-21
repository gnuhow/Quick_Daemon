# PySNMP SMI module. Autogenerated from smidump -f python LANGTAG-TC-MIB
# by libsmi2pysnmp-0.1.3 at Mon Apr  2 20:39:16 2012,
# Python version sys.version_info(major=2, minor=7, micro=2, releaselevel='final', serial=0)

# Imports

( Integer, ObjectIdentifier, OctetString, ) = mibBuilder.importSymbols("ASN1", "Integer", "ObjectIdentifier", "OctetString")
( NamedValues, ) = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
( ConstraintsIntersection, ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ) = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsIntersection", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint")
( Bits, Integer32, ModuleIdentity, MibIdentifier, TimeTicks, mib_2, ) = mibBuilder.importSymbols("SNMPv2-SMI", "Bits", "Integer32", "ModuleIdentity", "MibIdentifier", "TimeTicks", "mib-2")
( TextualConvention, ) = mibBuilder.importSymbols("SNMPv2-TC", "TextualConvention")

# Types

class LangTag(TextualConvention, OctetString):
    displayHint = "1a"
    subtypeSpec = OctetString.subtypeSpec+ConstraintsUnion(ValueSizeConstraint(0,0),ValueSizeConstraint(2,63),)
    

# Objects

langTagTcMIB = ModuleIdentity((1, 3, 6, 1, 2, 1, 165)).setRevisions(("2007-11-09 00:00",))
if mibBuilder.loadTexts: langTagTcMIB.setOrganization("IETF Operations and Management (OPS) Area")
if mibBuilder.loadTexts: langTagTcMIB.setContactInfo("EMail: ops-area@ietf.org\nHome page: http://www.ops.ietf.org/")
if mibBuilder.loadTexts: langTagTcMIB.setDescription("This MIB module defines a textual convention for\nrepresenting BCP 47 language tags.")

# Augmentions

# Exports

# Module identity
mibBuilder.exportSymbols("LANGTAG-TC-MIB", PYSNMP_MODULE_ID=langTagTcMIB)

# Types
mibBuilder.exportSymbols("LANGTAG-TC-MIB", LangTag=LangTag)

# Objects
mibBuilder.exportSymbols("LANGTAG-TC-MIB", langTagTcMIB=langTagTcMIB)

