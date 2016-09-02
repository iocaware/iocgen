import os
import re
import hashlib
from ioc_writer import ioc_api

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError


class IOCAware_OpenIOC(Report):
    """Creates IOC XML Document from Cuckoo Analysis Results"""

    def run(self, results):
        """Invokes IOCAware OpenIOC script.
        @param results: Cuckoo results dict
        @raise CuckooReportError: if fails to write report
        """

        try:
            # Make call to create ioc from cuckoo results
            doCuckoo(results, self.options, self.reports_path)
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError("Failed to generate IOC results: %s" % e)


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

# Because of the amount of noise going to broadcast and
# to the VM's IP, we exclude these from the IOC, again
# because we consider them of less value
excludedips = ['192.168.56.101', '192.168.56.255']


def addStrings(xmldoc, parentnode, strings):
    # This simply adds an AND block of the strings found
    if len(strings) > 0:
        stringsind = ioc_api.make_indicator_node("AND")
        for string in strings:
            stringsinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/StringList/string", content=string, content_type="string")
            stringsind.append(stringsinditem)
        parentnode.append(stringsind)
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


def createMetaData(xmldoc, parentnode, metadata):
    # load in the file name. It won't always be the actual file name
    # because dionaea renames it with the md5 hash...but it might
    # be the actual name
    #
    # As well, the items here generally won't change, so they are being
    # put in an AND block
    and_item = ioc_api.make_indicator_node('AND')
    if metadata['malfilename'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/FileName", content=str(metadata['malfilename']), content_type="string")
        and_item.append(inditem)

    # file size
    if metadata['malfilesize'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/SizeInBytes", content=str(metadata['malfilesize']), content_type="int")
        and_item.append(inditem)
    # file md5
    if metadata['malmd5'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/Md5Sum", content=metadata['malmd5'], content_type="md5")
        and_item.append(inditem)
    # md54k (http://www.md54k.org)
    # md54k is not part of Mandiant's list of indicators
    # so we are using our iocaware custom list (context_type="iocaware")
    # Please see the iocware.iocterms file
    if metadata['malmd54k'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/Md54ksum", content=metadata['malmd54k'], content_type="md5", context_type="iocaware")
        and_item.append(inditem)
    if metadata['malsha1'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/Sha1sum", content=metadata['malsha1'], content_type="sha1")
        and_item.append(inditem)
    if metadata['malsha256'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/Sha256sum", content=metadata['malsha256'], content_type="sha256")
        and_item.append(inditem)
    # sha512 is not included in the list of OpenIOC indicators
    # so the context_type="iocware" - please see the iocaware.iocterms file
    if metadata["malsha512"] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/Sha512sum", content=metadata['malsha512'], content_type="sha512", context_type="iocaware")
        and_item.append(inditem)
    # SSDeep also isn't included in the list of OpenIOC indicators
    if metadata["malssdeep"] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/Ssdeep", content=metadata["malssdeep"], content_type="ssdeep", context_type="iocaware")
        and_item.append(inditem)
    if metadata['malfiletype'] != "":
        inditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/Type", content=metadata['malfiletype'], content_type="string")
        and_item.append(inditem)
    parentnode.append(and_item)

    peinfoind = ioc_api.make_indicator_node("OR")
    if len(metadata['iocimports']) > 0:
        for importfunc in metadata['iocimports']:
            importinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/ImportedModules/Module/ImportedFunctions/string", content=importfunc, content_type="string")
            peinfoind.append(importinditem)
    if len(metadata['iocexports']) > 0:
        for exportfunc in metadata['iocexports']:
            exportinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/Exports/ExportedFunctions/string", content=exportfunc, content_type="string")
            peinfoind.append(exportinditem)
    if len(metadata['badpesections']) > 0:
        for section in metadata['badpesections']:
            sectionind = ioc_api.make_indicator_node("AND")
            sectioninditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/Sections/Section/Name", content=section[0], content_type="string")
            sectionind.append(sectioninditem)

            sectioninditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/Sections/Section/SizeInBytes", content=str(section[1]), content_type="int")
            sectionind.append(sectioninditem)

            sectioninditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/PEInfo/Sections/Section/Entropy/CurveData/float", content=str(section[2]), content_type="float")
            sectionind.append(sectioninditem)
            peinfoind.append(sectionind)

    # Include any PE Version Information
    if len(metadata['versioninfo']) > 0:
        infoind = ioc_api.make_indicator_node("AND")
        for infoitem in metadata['versioninfo']:
            if metadata['versioninfo'][infoitem] != "" and metadata['versioninfo'][infoitem] is not None:
                if "Version" in infoitem:
                    itemvalue = str(metadata['versioninfo'][infoitem]).replace(", ", ".")
                else:
                    itemvalue = str(metadata['versioninfo'][infoitem])
                infoitemsearch = "FileItem/PEInfo/VersionInfoItem/" + infoitem
                infoinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search=infoitemsearch, content=str(itemvalue), content_type="string")
                infoind.append(infoinditem)
                peinfoind.append(infoind)
    parentnode.append(peinfoind)


def createDynamicIndicators(xmldoc, parentnode, dynamicindicators):
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

    ind = ioc_api.make_indicator_node("OR")

    if filescreated:
        createdfilesind = ioc_api.make_indicator_node("OR")
        for createdfile in dynamicindicators['droppedfiles']:
            createdfilesinditem = ioc_api.make_indicatoritem_node(condition="is", document="FileItem", search="FileItem/FilenameCreated", content=createdfile[0], content_type="string")
            createdfilesind.append(createdfilesinditem)
        ind.append(createdfilesind)
    if processesstarted:
        processesind = ioc_api.make_indicator_node("OR")
        for process in dynamicindicators['processes']:
            startedprocessesind = ioc_api.make_indicator_node("AND")
            # Process name
            startedprocessesitem = ioc_api.make_indicatoritem_node(condition="is", document="ProcessItem", search="ProcessItem/name", content=process[0], content_type="string")
            startedprocessesind.append(startedprocessesitem)
            # Process pid
            startedprocessesitem = ioc_api.make_indicatoritem_node(condition="is", document="ProcessItem", search="ProcessItem/pid", content=str(process[1]), content_type="int")
            startedprocessesind.append(startedprocessesitem)
            # Process parent pid
            startedprocessesitem = ioc_api.make_indicatoritem_node(condition="is", document="ProcessItem", search="ProcessItem/parentpid", content=str(process[2]), content_type="int")
            startedprocessesind.append(startedprocessesitem)

            processesind.append(startedprocessesind)
        ind.append(processesind)
    if regkeyscreated:
        regkeyind = ioc_api.make_indicator_node("AND")
        for regkey in dynamicindicators['regkeys']:
            createdregkeysind = ioc_api.make_indicatoritem_node(condition="is", document="RegistryItem", search="RegistryItem/KeyPath", content=regkey, content_type="string")
            regkeyind.append(createdregkeysind)
        ind.append(regkeyind)
    if mutexescreated:
        mutexkeyind = ioc_api.make_indicator_node("OR")
        for mutex in dynamicindicators['mutexes']:
            createdmutexesind = ioc_api.make_indicatoritem_node(condition="contains", document="ProcessItem", search="ProcessItem/HandList/Handl/Name", content=mutex, content_type="string")
            mutexkeyind.append(createdmutexesind)
        ind.append(mutexkeyind)
    if hostscontacted:
        hostsind = ioc_api.make_indicator_node("OR")
        for host in dynamicindicators['hosts']:
            hostsinditem = ioc_api.make_indicatoritem_node(condition="is", document="PortItem", search="PortItem/remoteIP", content=host, content_type="string")
            hostsind.append(hostsinditem)
        ind.append(hostsind)
    parentnode.append(ind)
    return


def doCuckoo(results, options, reports_path):
    # Available cuckoo result structures
    #
    # info
    # signatures
    # static
    # dropped
    # behavior
    # target
    # debug
    # success
    # strings
    # network

    # Set up some of our variables by pulling either specific
    # values, or sections from the report
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
    isPE = False

    # PE file (EXE or DLL), just executable (DOS?) or other
    malfiletype = ''
    if "PE32" in fileitems['type'].upper():
        isPE = True
        if "DLL" in fileitems['type'].upper():
            malfiletype = "Dll"
        else:
            malfiletype = "Executable"

    # MD54K - From Chris Hudel
    malmd54k = doMD54K(fileitems['path'])

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

    # create our base/skeletal IOC
    desc = 'IOCAware OpenIOC Auto-Generated IOC for ' + malfilename
    ioc = ioc_api.IOC(description=desc, author='IOCAware')
    initindicator = ioc.top_level_indicator

    # Create our metadata dictionary for getting the
    # metadata values int the IOC
    metadata = {'malfilename': malfilename, 'malmd5': malmd5, 'malsha1': malsha1, 'malsha256': malsha256, 'malsha512': malsha512,
                'malmd54k': malmd54k, 'malfilesize': malfilesize, 'malssdeep': malssdeep, 'malfiletype': malfiletype,
                'iocexports': iocexports, 'iocimports': iocimports, 'badpesections': badpesections, 'versioninfo': versioninfo}
    # add metadata to the IOC
    createMetaData(ioc, initindicator, metadata)

    # add strings to the IOC
    addStrings(ioc, initindicator, strings)

    # create our dictionary of dynamic indicators
    dynamicindicators = {"droppedfiles": droppedfiles, "processes": processes, "regkeys": regkeys, 'mutexes': mutexes, 'hosts': hosts}

    # add dynamic indicators to the IOC
    createDynamicIndicators(ioc, initindicator, dynamicindicators)

    # write out the IOC
    output_dir_format = options.get("output_dir", "{reports_path}")
    output_dir = output_dir_format.format(reports_path=reports_path)
    ioc_api.write_ioc(ioc.root, output_dir)

    return
