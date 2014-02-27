from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource
from stix.indicator import Indicator

from cybox.common import Time
from cybox.common import Hash
from cybox.core import Observables
from cybox.core import Observable
from cybox.objects.file_object import File
from cybox.objects.win_executable_file_object import WinExecutableFile
from cybox.objects.win_executable_file_object import PEImportedFunction
from cybox.objects.win_executable_file_object import PEImportedFunctions
from cybox.objects.win_executable_file_object import PEImportList
from cybox.objects.win_executable_file_object import PEImport
from cybox.objects.win_executable_file_object import PEExportedFunction
from cybox.objects.win_executable_file_object import PEExportedFunctions
from cybox.objects.win_executable_file_object import PEExports
from cybox.objects.win_executable_file_object import PESectionList
from cybox.objects.win_executable_file_object import PESection
from cybox.objects.win_executable_file_object import PESectionHeaderStruct
from cybox.objects.win_executable_file_object import Entropy
from cybox.objects.win_executable_file_object import PEResourceList
from cybox.objects.win_executable_file_object import PEVersionInfoResource
from cybox.objects.win_file_object import WinFile
from cybox import helper

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

import hashlib
import re
from datetime import datetime

import inspect

#print(inspect.getmembers(PEImportedFunctions))#, predicate=inspect.ismethod))

class IOCAware_STIX(Report):
        """Creates STIX XML Document from Cuckoo Analysis Results"""

        def run(self, results):
                """Invokes IOCAware script.
                @param results: Cuckoo results dict
                @raise CuckooReportError: if fails to write report
                """

                try:
                        # Make call to create ioc from cuckoo results
                        doCuckoo(results)
                except (UnicodeError, TypeError, IOError) as e:
                        raise CuckooReportError("Failed to generate IOCAware_STIX results: %s" % e)

# This is where the script will
# write the IOCs
IOCLOCATION="/home/iocaware/Documents/stix"

# Since cuckoo dumps ALL imports, we only want to grab those
# that we consider "suspicious" so that the IOC isn't too
# verbose
suspiciousimports = ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'ReadProcessMemory', 'CreateProcess',
          'WinExec', 'ShellExecute', 'HttpSendRequest', 'internetReadFile', 'InternetConnect', 'CreateService',
          'StartService', 'WriteFile', 'RegSetValueEx', 'WSAstartup', 'InternetOpen', 'InternetOpenUrl', 'InternetReadFile',
          'CreateMutex', 'OpenSCManager', 'OleInitialize', 'CoInitializeEx', 'Navigate', 'CoCreateInstance', 'GetProcAddress',
          'SamIConnect', 'SamrQueryInformationUser', 'SamIGetPrivateData', 'SetWindowsHookEx', 'GetAsyncKeyState',
          'GetForegroundWindow', 'AdjustTokenPrivlieges', 'LoadResource']

# PE sections one feels it's safe to leave out of the IOC
goodpesections = ['.text', '.code', 'CODE', 'INIT', 'PAGE']

# Because of the amount of noise going to broadcast and
# to the VM's IP, we exclude these from the IOC, again
# because we consider them of less value
excludedips = ['192.168.56.101', '192.168.56.255']

def addStrings(strings):
	# This simply adds an AND block of the strings found
        if len(strings) > 0:
                for string in strings:
			print(string)
        else:
                return

def doStrings(strings):
        # Very simple regexes for IPv4 and email - these can be
        # modified and/or added to
        emailregex = re.compile(r'[A-Za-z0-9\.-_%]+@[A-Za-z0-9\.-_]+\.[A-Za-z]{2,6}')
        ipregex = re.compile(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

        emails = filter(lambda i: emailregex.search(i), strings)
        ips = filter(lambda i: ipregex.search(i), strings)

        return list(set(emails)) + list(set(ips))

def doMD54K(filename):
        # Here we take the first 4k bytes of
        # the binary and grab it's MD5, as per the work of
        # Christopher Hudel (with Dr. Shehab advising)
        # Find out more at:
        # http://www.md54k.org
        md54k = ""
        f = open(filename, 'r')
        first4k = f.read(4096)
        md54k = hashlib.md5(first4k).hexdigest()

        return md54k

def createMetaData(stix_package, metadata):
	indicator = Indicator()

	fl = WinExecutableFile()
	if metadata["malfilename"] != "":
		fl.file_name = metadata["malfilename"]
	if metadata["malmd5"] != "":
		fl.md5 = metadata["malmd5"]
	if metadata["malsha1"] != "":
		fl.sha1 = metadata["malsha1"]
	if metadata["malsha256"] != "":
		fl.sha256 = metadata["malsha256"]
	if metadata["malsha512"] != "":
		fl.sha512 = metadata["malsha512"]
	if metadata["malmd54k"] != "":
		md54k = Hash()
		md54k.simple_hash_value = metadata["malmd54k"]
		h = Hash(md54k, Hash.TYPE_OTHER)
		fl.add_hash(h)
	if metadata["malssdeep"] != "":
		ssdeep = Hash()
		ssdeep.simple_hash_value = metadata["malssdeep"]
		h = Hash(ssdeep, Hash.TYPE_SSDEEP)
		fl.add_hash(h)
	if metadata["malfilesize"] != "":
		fl.size_in_bytes = metadata["malfilesize"]
	if metadata["malfiletype"] != "":
		fl.file_format = metadata["malfiletype"]

	peindicator = Indicator()
	peimportlist = PEImportList()
	peimport = PEImport()
	peimportedfunctions = PEImportedFunctions()
	if len(metadata['iocimports']) > 0:
                for importfunc in metadata['iocimports']:
			peif = PEImportedFunction()
			peif.function_name = importfunc
			peimportedfunctions.append(peif)

	peimport.imported_functions = peimportedfunctions
        peimportlist.append(peimport)

	peexports = PEExports()
	peexportedfunctions = PEExportedFunctions()
	if len(metadata['iocexports']) > 0:
		for exportfunc in metadata['iocexports']:
			peef = PEExportedFunction()
			peef.function_name = exportfunc
			peexportedfunctions.append(peef)

	peexports.exported_functions = peexportedfunctions

	pesectionlist = PESectionList()
	if len(metadata['badpesections']) > 0:
		for section in metadata['badpesections']:
			pesection = PESection()
			pesectionheader = PESectionHeaderStruct()
			entropy = Entropy()
			pesectionheader.name = section[0]
			if len(section[1]) > 0:
				data_size = section[1].replace("0x", "")
				if len(data_size) % 2 != 0:
					data_size = "0" + data_size
			pesectionheader.size_of_raw_data = data_size
			entropy.value = float(section[2])
			pesection.entropy = entropy
			pesection.section_header = pesectionheader
			pesectionlist.append(pesection)

	peresourcelist = PEResourceList()
	peversioninforesource = PEVersionInfoResource()
	if len(metadata['versioninfo']) > 0:
		peversioninforesource.comments = str(metadata['versioninfo']['Comments']) if (metadata['versioninfo']['Comments'] is not None) else ""
		peversioninforesource.companyname = str(metadata['versioninfo']['CompanyName']) if (metadata['versioninfo']['CompanyName'] is not None) else ""
		peversioninforesource.filedescription = str(metadata['versioninfo']['FileDescription']) if (metadata['versioninfo']['FileDescription'] is not None) else ""
		peversioninforesource.fileversion = str(metadata['versioninfo']['FileVersion']).replace(", ", ".") if (metadata['versioninfo']['FileVersion'] is not None) else ""
		peversioninforesource.internalname = str(metadata['versioninfo']['InternalName']) if (metadata['versioninfo']['InternalName'] is not None) else ""
		peversioninforesource.langid = ""
		peversioninforesource.legalcopyright = str(metadata['versioninfo']['LegalCopyright']) if (metadata['versioninfo']['LegalCopyright'] is not None) else ""
		peversioninforesource.originalfilename = str(metadata['versioninfo']['OriginalFilename']) if (metadata['versioninfo']['OriginalFilename'] is not None) else ""
		peversioninforesource.privatebuild = str(metadata['versioninfo']['PrivateBuild']) if (metadata['versioninfo']['PrivateBuild'] is not None) else ""
		peversioninforesource.productname = str(metadata['versioninfo']['ProductName']) if (metadata['versioninfo']['ProductName'] is not None) else ""
		peversioninforesource.productversion = str(metadata['versioninfo']['ProductVersion']).replace(", ", ".") if (metadata['versioninfo']['ProductVersion'] is not None) else ""
		peversioninforesource.specialbuild = str(metadata['versioninfo']['SpecialBuild']) if (metadata['versioninfo']['SpecialBuild'] is not None) else ""

	peresourcelist.append(peversioninforesource)
				

	fl.imports = peimportlist
	fl.exports = peexports
	fl.sections = pesectionlist
	fl.resources = peresourcelist
	print(peresourcelist.to_xml())

	indicator.add_observable(Observable(fl))

	stix_package.add_indicator(indicator)

def doCuckoo(results):
	fileitems = results['target']['file']
        staticitems = results['static']
        info = results['info']

        malfilename = fileitems['name']
        malfilesize = fileitems['size']
        malmd5 = fileitems['md5']
        malsha1 = fileitems['sha1']
        malsha256 = fileitems['sha256']
        malsha512 = fileitems['sha512']
        malssdeep = fileitems['ssdeep']
	malfiletype = fileitems["type"]

	# MD54K - From Chris Hudel
        malmd54k = doMD54K(fileitems['path'])

        # Suspicious PE imports
        iocimports = []
        try:
                for imports in staticitems['pe_imports']:
                        for item in imports['imports']:
                                if item['name'] in suspiciousimports :
                                        iocimports.append(item['name'])
        except:
                pass

        #rsrcentries = []

        # PE sectionis
        badpesections = []
        try:
                for sections in staticitems['pe_sections']:
                        if sections['name'] not in goodpesections:
                                badpesection = [sections['name'], sections['size_of_data'], str(sections['entropy'])]
                                badpesections.append(badpesection)
        except:
                pass

        # PE Exports            
        iocexports = []
        try:
                for exportfunc in staticitems['pe_exports']:
                        iocexports.append(exportfunc['name'])
        except:
                pass

        # PE Version Info
        versioninfo = dict.fromkeys(['LegalCopyright', 'InternalName', 'FileVersion', 'CompanyName', 'PrivateBuild', \
                                        'LegalTrademarks', 'Comments', 'ProductName', 'SpecialBuild', 'ProductVersion', \
                                        'FileDescription', 'OriginalFilename'])

	if 'pe_versioninfo' in staticitems:
                for item in staticitems['pe_versioninfo']:
                        if item['name'] in versioninfo:
                                versioninfo[item['name']] = item['value']

        # Dropped files 
        droppedfiles = []
        try:
                for droppedfile in results['dropped']:
                        droppedfiles.append([droppedfile['name'], droppedfile['size'], droppedfile['md5'], droppedfile['sha1'], \
                                             droppedfile['sha256'], droppedfile['sha512']])
        except:
                pass

        # Hosts contacted. This will exclude
        # localhost, broadcast and any other 'noise'
        # as indicated by excludedips
        hosts = []
        try:
                for host in results['network']['hosts']:
                        if host not in excludedips:
                                hosts.append(host)
        except:
                pass

        # Mutexes
        mutexes = []
        try:
                for mutex in results['behavior']['summary']['mutexes']:
                        mutexes.append(mutex)
        except:
                pass

	# Processes
        processes = []
        try:
                for process in results['behavior']['processes']:
                        processes.append([process['process_name'], process['process_id'], process['parent_id']])
        except:
                pass

        # grab the string results
        # currently these are simple
        # regexes for IPv4 addresses and
        # emails
        strings = doStrings(results['strings'])

        # Registry Keys
        # This uses modified cuckoo source code to only
        # pull the Registry keys created, instead
        # of those created OR just opened
        regkeys = results['behavior']['summary']['keys']

	# Create our metadata dictionary for getting the
        # metadata values int the IOC
        metadata = {'malfilename':malfilename, 'malmd5':malmd5, 'malsha1':malsha1, 'malsha256':malsha256, 'malsha512':malsha512, \
                    'malmd54k':malmd54k, 'malfilesize':malfilesize, 'malssdeep':malssdeep, 'malfiletype':malfiletype, \
                    'iocexports':iocexports, 'iocimports':iocimports, 'badpesections':badpesections, 'versioninfo':versioninfo}

	stix_package = STIXPackage()
	stix_header = STIXHeader()
	stix_header.description = "IOCAware Auto-Generated STIX IOC Document for " + malfilename
	stix_header.information_source = InformationSource()
	stix_header.information_source.time = Time()
	stix_header.information_source.time.produced_time = datetime.now()
	stix_package.stix_header = stix_header

	createMetaData(stix_package, metadata)

	print(stix_package.to_xml())

