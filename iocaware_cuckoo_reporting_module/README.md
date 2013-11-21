IOCAware Cuckoo Reporting Module
======

Description:

This is the base reporting module for Cuckoo (currently built against 0.6.0) for automatically generating IOCs

DEPENDENCIES

1) Cuckoo 0.6.0 - you will need an actual working version of cuckoo for this to work
  http://www.cuckoosandbox.org
  
2) Relies on Mandiant's ioc_writer, found here (for the OpenIOC portion):
  https://github.com/mandiant/ioc_writer


INSTALLATION:

1) Modify CUCKOO_HOME/conf/reporting.conf at the end with the following:

[iocaware]<br/>
enabled=on

2) Put the scription, iocaware.py into the following directory:

CUCKOO_HOME/modules/reporting/iocaware.py

3) OPTIONAL - currently, the reporting module returns registry keys that are been opened or created. I modified the
cuckoo code to only pull created keys (for now). To do this: 
   - open up CUCKOO_HOME/modules/processing.behavior.py
   - find the line with "RegCreateKeyEx" (line 276 in the version of Cuckoo I've been using)
   - change it to: if call["api"].startswith("RegCreateKeyEx"):

ADDITIONAL NOTES:

There are several sections of the iocaware.py script that can be modified for more customized use:

   - Change the IOCLOCATION constant to the location where you want the IOCs created (default is /hom/iocaware/Documents/iocs)
   - Add/Delete/Modify the API calls in the suspiciousimports variable; items in this variable will be included in the IOC
   - Add/Delete/Modify the pe sections considered "good" in the goodpesections variable; items in this variable will NOT be in the IOC
   - Add/Delete/Modify the IP's in the excludeips variable ; items in this variable will NOT be in the IOC
   - Add/Delete/Modify the string regexes in the doStrings method to pull more and/or better strings out of the binary
