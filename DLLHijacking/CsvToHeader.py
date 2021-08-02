import pefile
import os
import xml.etree.ElementTree as ET
import argparse

############## Check PE ##############
#

class CheckPE():
    def __init__(self,pathFile):
        self.pathFile = pathFile
        self.exist = os.path.isfile(pathFile)
        if(self.exist):
            self.pe = pefile.PE(pathFile)
        
    def PeArch(self):
        arch = ""
        if self.pe.FILE_HEADER.Machine == 0x014c:
            arch = "x86"
        if self.pe.FILE_HEADER.Machine == 0x8664:
            arch = "x64" 
        return arch

    def GetManifest(self):
        if self.PeArch() == "x64" and hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
                if name and hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                manifest = self.pe.get_data(
                                    resource_lang.data.struct.OffsetToData,
                                    resource_lang.data.struct.Size)
                                if 'MANIFEST' in name:
                                    return manifest
        return b""

    # Check <autoElevate>true</autoElevate>
    def isAutoEleveate(self,manifest):
        try:
            myroot = ET.fromstring(manifest)
            for xml in myroot.findall('{urn:schemas-microsoft-com:asm.v3}application'):
                for application in xml:
                    if("windowsSettings" in application.tag):
                        for windowsSettings in application:
                            if("autoElevate" in windowsSettings.tag):
                                return windowsSettings.text == "true"
        except ET.ParseError as error:
            return False
        return False

    # Allows requireAdministrator, highestAvailable, asInvoker
    def isRequireAdministrator(self, manifest):
        try:
            myroot = ET.fromstring(manifest)
            for xml in myroot.findall('{urn:schemas-microsoft-com:asm.v3}trustInfo'):
                for trustInfo in xml:
                    if("security" in trustInfo.tag):
                        for requestedPrivileges in trustInfo:
                            if("requestedPrivileges" in requestedPrivileges.tag):
                                for requestedExecutionLevel in requestedPrivileges:
                                    if("requestedExecutionLevel" in requestedExecutionLevel.tag):
                                        level = requestedExecutionLevel.attrib["level"]
                                        return  level == "requireAdministrator" or level == "highestAvailable" or level == "asInvoker"
        except ET.ParseError as error:
            return False
        return False

    def ExeCheck(self):
        if(not self.exist):
            return False
        manifest = self.GetManifest().decode()
        return manifest != "" and self.isAutoEleveate(manifest) and self.isRequireAdministrator(manifest)

    def CheckValidDll(self,dllName):
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            if(entry.dll.decode() == dllName):
                return True
        return False

#
############## Check PE ##############



############# Gen struct #############
#

def CreateStruct(dllList):
    print("\ntypedef struct {\n"
    "\tconst char* name;\n"
    "\tconst char** dllTable;\n"
    "\tint tableSize;\n"
    "} DllList;\n")

    print("DllList dllList[] = {")
    for dll in dllList:
        print("\t{" + dll[0] + ", " + dll[1] + ", sizeof("+dll[1] +") / sizeof(char*)},")
    print("};")

def ReadFromCSV(isCheckDllImport, filePath):
    dllList = []
    with open(filePath, 'r') as pFile:
        Lines = pFile.readlines()
        oldExe = ""

        for line in Lines:
            if("DllMain" in line.strip()):
                    strCut = line.strip().split(",")
                    AutoElevated = strCut[0]
                    exeName = strCut[1]
                    dllName = strCut[2]
                    exeFullPath = "c:\\windows\\system32\\" + exeName[1:-1]
                    checkPE = CheckPE(exeFullPath)

                    if(checkPE.ExeCheck()):
                        if(oldExe != exeName):
                            varName = exeName[1:-5].replace("-","_").replace(".","_") + AutoElevated[0]
                            dllList.append([exeName,varName])
                            if(oldExe != ""):
                                print("};")
                            print("const char*",varName + "[] = {")
                            oldExe = exeName
                        if(not isCheckDllImport):
                            print("\t"+dllName + ",")
                        elif(checkPE.CheckValidDll(dllName[1:-1])):
                            print("\t"+dllName + ",")
                        
        print("};")
        pFile.close()
    return dllList

#
############# Gen struct #############

def ManageArg():
    parser = argparse.ArgumentParser(description='CsvToHeader can be used to generate a header file from a CSV.', usage='%(prog)s -f [DLL_PATH] -c')
    parser.version = 'CsvToHeader version: 0.0.1-Dev'
    parser.add_argument('-f',  metavar=' [DLL_PATH]', type=str, help='Path of the csv to convert (default="dll_hijacking_candidates.csv")', default='dll_hijacking_candidates.csv')
    parser.add_argument('-c',  help='Enable import dll in PE (default=False)', action='store_true', default=False)
    parser.add_argument('-v', '--version', action='version', help='Show program\'s version number and exit')
    try:
        args = parser.parse_args()
    except:
        print("[x] Fail to parse arguments !")
        exit(1)
    return {'dllPath' : args.f,'isCheckDllImport' : args.c}

def main():
    userConfig = ManageArg()

    dllList = ReadFromCSV(userConfig['isCheckDllImport'],userConfig['dllPath'])
    CreateStruct(dllList)
    exit(0)

main()