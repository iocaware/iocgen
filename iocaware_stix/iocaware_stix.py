import stix.utils as utils
from stix.core import STIXPackage, STIXHeader
from stix.common import InformationSource
from stix.indicator import Indicator

from cybox.common import Time
from cybox.common import Hash
from cybox.common import HashList
from cybox.common import ExtractedFeatures
from cybox.common import ExtractedStrings
from cybox.common import ExtractedString
from cybox.common import String
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
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.socket_address_object import SocketAddress
from cybox.objects.win_mutex_object import WinMutex
from cybox.objects.win_handle_object import WinHandle
from cybox.objects.process_object import Process
from cybox.objects.win_file_object import WinFile
from cybox.objects.win_registry_key_object import WinRegistryKey
from cybox import helper

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

import hashlib
import re
import sys
from datetime import datetime
import uuid

import inspect

# print(inspect.getmembers(ExtractedString))#, predicate=inspect.ismethod))


class IOCAware_STIX(Report):
    """Creates STIX XML Document from Cuckoo Analysis Results"""

    def run(self, results):
        """Invokes IOCAware script.
        @param results: Cuckoo results dict
        @raise CuckooReportError: if fails to write report
        """

        try:
            # Make call to create ioc from cuckoo results
            doCuckoo(results, self.options, self.reports_path)
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate IOCAware_STIX results: %s" % e)

# Since cuckoo dumps ALL imports, we only want to grab those
# that we consider "suspicious" so that the IOC isn't too
# verbose
suspiciousimports = ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'ReadProcessMemory', 'CreateProcess',
                     'WinExec', 'ShellExecute', 'HttpSendRequest', 'InternetReadFile', 'InternetConnect', 'CreateService',
                     'StartService', 'WriteFile', 'RegSetValueEx', 'WSAstartup', 'InternetOpen', 'InternetOpenUrl', 'InternetReadFile',
                     'CreateMutex', 'OpenSCManager', 'OleInitialize', 'CoInitializeEx', 'Navigate', 'CoCreateInstance', 'GetProcAddress',
                     'SamIConnect', 'SamrQueryInformationUser', 'SamIGetPrivateData', 'SetWindowsHookEx', 'GetAsyncKeyState',
                     'GetForegroundWindow', 'AdjustTokenPrivileges', 'LoadResource']

# PE sections one feels it's safe to leave out of the IOC
goodpesections = ['.text', '.code', 'CODE', 'INIT', 'PAGE']

# def addStrings(stix_package, wfe, strings):


def addStrings(wfe, strings):
    # This simply adds an AND block of the strings found
    extractedfeatures = ExtractedFeatures()
    extractedstrings = ExtractedStrings()
    if len(strings) > 0:
        for string in strings:
            extractedstring = ExtractedString()
            extractedstring.string_value = string
            extractedstring.length = len(string)
            extractedstrings.append(extractedstring)
    else:
        return

    extractedfeatures.strings = extractedstrings
    wfe.extracted_features = extractedfeatures
    #members = [attr for attr in dir(WinExecutableFile()) if not callable(attr) and not attr.startswith("__")]


def doStrings(strings):
    # Very simple regexes for IPv4, URLs,  and email - these can be
    # modified and/or added to
    emailregex = re.compile(r'[A-Za-z0-9\.-_%]+@[A-Za-z0-9\.-_]+\.[A-Za-z]{2,6}')
    ipregex = re.compile(r'^(| |\(){1}([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}){1}$')
    #ipregex = re.compile(r'(([2][5][0-5]\.)|([2][0-4][0-9]\.)|([0-1]?[0-9]?[0-9]\.)){3}(([2][5][0-5])|([2][0-4][0-9])|([0-1]?[0-9]?[0-9]))')
    #ipregex = re.compile(r'[^\.]([1-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])){1}\.([1-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])){1}\.([1-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])){1}\.([1-9]|[1-9][0-9]|1([0-9][0-9])|2([0-4][0-9]|5[0-5])){1}[^\.]')
    urlregex = re.compile(r'(http|https|ftp|mail)\:\/')

    emails = filter(lambda i: emailregex.search(i), strings)
    ips = filter(lambda i: ipregex.search(i), strings)
    urls = filter(lambda i: urlregex.search(i), strings)

    return list(set(emails)) + list(set(ips)) + list(set(urls))


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

# def createMetaData(stix_package, metadata):


def createMetaData(stix_package, metadata, strings):
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

    addStrings(fl, strings)

    indicator.add_observable(Observable(fl))

    stix_package.add_indicator(indicator)
    return fl


def createDynamicIndicators(stix_package, dynamicindicators):
    filescreated = False
    processesstarted = False
    regkeyscreated = False
    mutexescreated = False
    hostscontacted = False
    hasdynamicindicators = False

    # Here we are just testing to see if the report had any
    # of the various dynamic indicator types so we know whether
    # or not to process them at all
    if len(dynamicindicators['droppedfiles']) > 0:
        filescreated = True
        hasdynamicindicators = True
    if len(dynamicindicators['processes']) > 0:
        processesstarted = True
        hasdynamicindicators = True
    if len(dynamicindicators['regkeys']) > 0:
        regkeyscreated = True
        hasdynamicindicators = True
    if len(dynamicindicators['mutexes']) > 0:
        mutexescreated = True
        hasdynamicindicators = True
    if len(dynamicindicators['hosts']) > 0:
        hostscontacted = True
        hasdynamicindicators = True

    if not hasdynamicindicators:
        return

    if filescreated:
        createdfilesind = Indicator()
        for createdfile in dynamicindicators['droppedfiles']:
            createdfilename = File()
            createdfilename.file_name = createdfile[0]
            createdfilename.size_in_bytes = createdfile[1]
            createdfilename.md5 = createdfile[2]
            createdfilename.sha1 = createdfile[3]
            createdfilename.sha256 = createdfile[4]
            createdfilesind.add_observable(Observable(createdfilename))

        stix_package.add_indicator(createdfilesind)
    if processesstarted:
        procindicator = Indicator()
        for process in dynamicindicators['processes']:
            # Process name
            processname = process[0]
            # Process pid
            processpid = process[1]
            # Process parent pid
            processparentpid = process[2]

            proc = Process()
            proc.name = processname
            proc.pid = processpid
            proc.parent_pid = processparentpid
            procindicator.add_observable(Observable(proc))

        stix_package.add_indicator(procindicator)
    if regkeyscreated:
        regindicator = Indicator()
        keypath = WinRegistryKey()

        for regkey in dynamicindicators['regkeys']:
            keypath = WinRegistryKey()
            keypath.key = regkey
            regindicator.add_observable(Observable(keypath))

        stix_package.add_indicator(regindicator)
    if mutexescreated:
        mutexind = Indicator()
        for mutex in dynamicindicators['mutexes']:
            winhandle = WinHandle()
            winhandle.name = mutex
            winmutex = WinMutex()
            winmutex.handle = winhandle
            mutexind.add_observable(Observable(winmutex))
        stix_package.add_indicator(mutexind)
    if hostscontacted:
        networkconnectionind = Indicator()
        for host in dynamicindicators['hosts']:
            networkconnection = NetworkConnection()
            socketaddress = SocketAddress()
            socketaddress.ip_address = host
            networkconnection.destination_socket_address = socketaddress
            networkconnectionind.add_observable(Observable(networkconnection))
        stix_package.add_indicator(networkconnectionind)
    return


def stringscmd(filename):
    with open(filename) as f:
        data = f.read()
    return re.findall(r"[A-Za-z0-9\-\[\]\.:;<>,\$%_]{4,}", data)


def doCuckoo(results, options, reports_path):
    malfilename = ""
    memstrings = []

    try:
        fileitems = results['target']['file']
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

        #memfile = fileitems['path'][0:len(fileitems['path']) - 64] + "../analyses/" + str(results['info']['id']) + "/memory.dmp"
        #memstrings = doStrings(stringscmd(memfile))

    except:
        fileitems = []
        pass

    staticitems = results['static']
    info = results['info']

    # Suspicious PE imports
    iocimports = []
    try:
        for imports in staticitems['pe_imports']:
            for item in imports['imports']:
                if item['name'] in suspiciousimports:
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
    versioninfo = dict.fromkeys(['LegalCopyright', 'InternalName', 'FileVersion', 'CompanyName', 'PrivateBuild',
                                 'LegalTrademarks', 'Comments', 'ProductName', 'SpecialBuild', 'ProductVersion',
                                 'FileDescription', 'OriginalFilename'])

    if 'pe_versioninfo' in staticitems:
        for item in staticitems['pe_versioninfo']:
            if item['name'] in versioninfo:
                versioninfo[item['name']] = item['value']

    # Dropped files
    droppedfiles = []
    try:
        for droppedfile in results['dropped']:
            droppedfiles.append([droppedfile['name'], droppedfile['size'], droppedfile['md5'], droppedfile['sha1'],
                                 droppedfile['sha256'], droppedfile['sha512']])
    except:
        pass

    # Hosts contacted. This will exclude
    # localhost, broadcast and any other 'noise'
    # as indicated by excludedips
    hosts = []
    try:
        excludedips = [ip for ip in options.get('excludedips', '').split(',') if ip]
        for host in results['network']['hosts']:
            if host not in excludedips:
                hosts.append(host)
    except:
        pass

    # Mutexes
    mutexes = []
    try:
        if 'mutex' in results['behavior']['summary']:
            # Cuckoo 2.0
            for mutex in results['behavior']['summary']['mutex']:
                mutexes.append(mutex)
        elif 'mutexes' in results['behavior']['summary']:
            # Cuckoo 1.x
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
    regkeys = []
    if 'regkey_written' in results['behavior']['summary']:
        # Cuckoo 2.0
        regkeys = results['behavior']['summary']['regkey_written']
    elif 'keys' in results['behavior']['summary']:
        # Cuckoo 1.x
        # This uses modified cuckoo source code to only
        # pull the Registry keys created, instead
        # of those created OR just opened
        regkeys = results['behavior']['summary']['keys']

    # Create our metadata dictionary for getting the
    # metadata values int the IOC
    metadata = {'malfilename': malfilename, 'malmd5': malmd5, 'malsha1': malsha1, 'malsha256': malsha256, 'malsha512': malsha512,
                'malmd54k': malmd54k, 'malfilesize': malfilesize, 'malssdeep': malssdeep, 'malfiletype': malfiletype,
                'iocexports': iocexports, 'iocimports': iocimports, 'badpesections': badpesections, 'versioninfo': versioninfo}

    dynamicindicators = {"droppedfiles": droppedfiles, "processes": processes, "regkeys": regkeys, 'mutexes': mutexes, 'hosts': hosts}

    if "namespace" in options:
        namespace_prefix, namespace_uri = options["namespace"].split(",", 1)
        utils.set_id_namespace({namespace_uri: namespace_prefix})

    stix_package = STIXPackage()
    package_uuid = stix_package.id_[-36:]

    stix_header = STIXHeader()
    desc = "IOCAware Auto-Generated IOC Document"
    if len(malfilename) > 0:
        desc += " " + malfilename

    stix_header.description = desc
    stix_header.information_source = InformationSource()
    stix_header.information_source.time = Time()
    stix_header.information_source.time.produced_time = datetime.now()
    stix_package.stix_header = stix_header

    #wfe = createMetaData(stix_package, metadata)
    #addStrings(stix_package, wfe, strings)
    createMetaData(stix_package, metadata, strings)
    createDynamicIndicators(stix_package, dynamicindicators)

    output_path_format = options.get("output_path", "{reports_path}/iocaware_stix.xml")
    output_path = output_path_format.format(
        uuid=package_uuid,
        reports_path=reports_path,
    )
    stixfile = open(output_path, "w")
    stixfile.write(stix_package.to_xml())
