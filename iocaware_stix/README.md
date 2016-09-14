IOCAware STIX Cuckoo Reporting Module
======

Description:

This is the base reporting module for Cuckoo (currently built against 0.6.0; confiremd to work with cuckoo 1.0 and 1.1.1) for automatically generating STIX IOCs

DEPENDENCIES

1) Cuckoo >= 0.6.0 - you will need an actual working version of cuckoo for this to work
  http://www.cuckoosandbox.org
  
2) Relies on python-stix >= 1.0.1.1. Follow instructions here (which will also take care of dependencies):
  https://github.com/STIXProject/python-stix


INSTALLATION:

1) Modify CUCKOO_HOME/conf/reporting.conf at the end with the following:
```ini
[iocaware_stix]
enabled=on

# (Optional) Namespace used in IDs, in the format "<prefix>,<uri>". Default: example,http://example.com
#namespace=cuckoo,http://cuckoosandbox.org

# (Optional) File path where the module outputs IOCs. "{uuid}" is replaced with UUID of IOC.
# "{reports_path}" is replaced with reports path (e.g. storage/analyses/1/reports).
# Default: {reports_path}/iocaware_stix.xml
#output_path=/home/iocaware/Documents/stix_iocs/iocaware_stix_{uuid}.xml

# (Optional) IPs excluded from the IOC
#excludedips=192.168.56.101,192.168.56.255
```

2) Put the script, iocaware_stix.py into the following directory:

CUCKOO_HOME/modules/reporting/iocaware_stix.py

3) OPTIONAL - currently, the reporting module returns registry keys that are been opened or created. I modified the
cuckoo code to only pull created keys (for now). To do this: 
   - open up CUCKOO_HOME/modules/processing.behavior.py
   - find the line with "RegCreateKeyEx" (line 276 in the version of Cuckoo I've been using)
   - change it to: if call["api"].startswith("RegCreateKeyEx"):

ADDITIONAL NOTES:

There are several sections of the iocaware_openioc.py script that can be modified for more customized use:

   - Add/Delete/Modify the API calls in the suspiciousimports variable; items in this variable will be included in the IOC
   - Add/Delete/Modify the pe sections considered "good" in the goodpesections variable; items in this variable will NOT be in the IOC
   - Add/Delete/Modify the string regexes in the doStrings method to pull more and/or better strings out of the binary
