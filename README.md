# SID2OID
ADCS Strong Mapping Utility

On May 10, 2022, Microsoft released their monthly Cumulative Update (KB5013941). With this update, they changed some core functionality related to how certificate-based authentication is processed, more described in detail in KB5014754.

Basically, with the update applied to your CAs, all issued certificates which builds the subject information from Active Directory will now include a new extension identified by the OID 1.3.6.1.4.1.311.25.2:

This script converts the SID to OID, so you can add it manually to the template or perform a request with certutil, etc.

PLASE, change your target SID before run.
