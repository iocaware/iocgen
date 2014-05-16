IOCAware STIX Cuckoo Reporting Module
======

NOTE: Compatibility with Cuckoo 1.2-dev has been verified, but changes have not been made to take advantage of any of the changes in Cuckoo. As well, further enhancements to take advantage of STIX itself need to be made (in addition to supporting STIX 1.1.1)

Description:

This is the base reporting module for Cuckoo (currently built against 0.6.0) for automatically generating STIX IOCs

DEPENDENCIES

1) Cuckoo 0.6.0 - you will need an actual working version of cuckoo for this to work
  http://www.cuckoosandbox.org
  
2) Relies on python-stix. Follow instructions here (which will also take care of dependencies):
  https://github.com/STIXProject/python-stix


INSTALLATION:

1) Modify CUCKOO_HOME/conf/reporting.conf at the end with the following:

[iocaware_stix]<br/>
enabled=on

2) Put the script, iocaware_stix.py into the following directory:

CUCKOO_HOME/modules/reporting/iocaware_stix.py

3) OPTIONAL - currently, the reporting module returns registry keys that are been opened or created. I modified the
cuckoo code to only pull created keys (for now). To do this: 
   - open up CUCKOO_HOME/modules/processing.behavior.py
   - find the line with "RegCreateKeyEx" (line 276 in the version of Cuckoo I've been using)
   - change it to: if call["api"].startswith("RegCreateKeyEx"):

ADDITIONAL NOTES:

There are several sections of the iocaware_openioc.py script that can be modified for more customized use:

   - Change the IOCLOCATION constant to the location where you want the IOCs created (default is /home/iocaware/Documents/stix_iocs)
   - Add/Delete/Modify the API calls in the suspiciousimports variable; items in this variable will be included in the IOC
   - Add/Delete/Modify the pe sections considered "good" in the goodpesections variable; items in this variable will NOT be in the IOC
   - Add/Delete/Modify the IP's in the excludeips variable ; items in this variable will NOT be in the IOC
   - Add/Delete/Modify the string regexes in the doStrings method to pull more and/or better strings out of the binary
