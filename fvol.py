#!/usr/bin/python
# Author: David Bernal Michelena
# Fast volatility: wrapper script that automates volatility plugin executions.
# Created: May 29, 2015
# Last modified: June 28, 2020
# License: CREATIVE COMMONS LICENSE BY-NC https://creativecommons.org/licenses/by-nc/4.0/

import os 
import re
import subprocess
import sys
import time

if not 3 <= len(sys.argv) < 5:
    print "Syntax: " + sys.argv[0] +" <Memory Dump full path> <Project Folder> [Volatility Profile (if not given it is obtained from imageinfo)]"
    sys.exit(1)

volatility_path = "vol.py"

try:
    subprocess.check_output([volatility_path,"-h"])
except Exception as e:
    print "Volatity program was not identifed."
    volatility_path = raw_input("Please provide volatility path: ").strip("\"")
    
    if not os.path.isfile(volatility_path):
        print "File does not exist: " + volatility_path
        sys.exit(1)
    else:
        volatility_path = "\"" + volatility_path + "\""
    
memoryDump = sys.argv[1]

if "\"" not in memoryDump:
    memoryDump = "\"" + memoryDump +  "\""
print "Memory Dump: "+ memoryDump

# plugin name, target operating system, enabled (1)|disabled (0), additional pluging parameters

analysisPlugins = [
    ["pstree -v", "all",1,""],
    ["pslist", "all",1,""],
    ["pstree", "all",1,""],
    ["consoles", "all",1,""],
    ["dlllist", "all",1,""],
    ["getsids", "all",1,""],
    ["svcscan", "all",1,""],
    ["cmdline", "all",1,""],
    ["sockets", "WinXP",1,""],
    ["sockscan", "WinXP",1,""],
    ["connscan", "WinXP",1,""],
    ["connections", "WinXP",1,""],
    ["imageinfo", "all",1,""],
    ["hivelist", "all",1,""],
    ["userassist", "all",1,""],
    ["getsids", "all",1,""],
    ["hashdump", "all",1,""],
    ["printkey", "all",1,"-K \"Microsoft\Windows\CurrentVersion\Run\"",""],
    ["netscan", "Win7-Win10x64-Win10x86",1,""],
    ["malfind", "all",1,""],
    ["ldrmodules", "all",1,""],
    ["modules", "all",1,""],
    ["modscan", "all",1,""],
    ["mutantscan", "all",1,""],
    ["handles", "all",1,""],
    ["filescan", "all",1,""],
    ["svcscan", "all",1,""],
    ["psscan", "all",1,""],
    ["cmdscan", "all",1,""],
    ["psxview", "all",1,""],    
    ["procdump", "all",1,"","--dump-dir","procdump"],
    ["malfind", "all",1,"","--dump-dir","maldump"],
    ["dlldump", "all",1,"","--dump-dir","dlldump"],
    ["moddump", "all",1,"","--dump-dir","moddump"],
    ["dumpfiles", "all",1,"","--dump-dir","dumpfiles"],
    ["dumpregistry", "all",1,"","--dump-dir","dumpregistry"],
    ["ssdt", "all",0,""],
    ["driverirp", "all",0,""],
    ["idt", "all",0,""],
    ["apihooks", "WinXP",0,"--quick"],
]


"""  Test plugin list
#analysisPlugins = [
    ["pstree -v", "all",1,""],
    ["pslist", "all",1,""],
    ["psscan", "all",1,""],
    ["consoles", "all",1,""],
]
"""
    
reload(sys);
sys.setdefaultencoding("utf8")

if sys.argv[2][-1] is not "/" or sys.argv[2][-1] is not "\\":
    workingFolder = sys.argv[2] + "/"
else:
    workingFolder = sys.argv[2]

if not (os.path.isdir(workingFolder)):
    os.makedirs(workingFolder)

logFile = workingFolder +  "audit.txt"

flog = open(logFile,"w")
flog.write("Memory Dump: " + memoryDump + "\n")
flog.write("Working Folder: " + workingFolder + "\n\n")
flog.close()

if len(sys.argv) == 4:
    Profile = sys.argv[3]
    print "Profile provided by the user: " + Profile
else:
    # If profile is not provided by the user, then run imageinfo and try every profile with pslist
    command = volatility_path + " -f "+memoryDump+ " imageinfo"
    print "command: " + command
    imageInfo = subprocess.check_output(command, shell=True)
    array = imageInfo.splitlines()   
    for line in array:
        print line
        if "Suggested Profile(s)" in line:
            suggestedProfileLine = line
            suggestedProfileList = line.replace("Suggested Profile(s) :","").split(",")
        elif "(Service Pack)" in line:
            imageType = line

    #suggestedProfileLine = "Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86 (instantiated as Win10x86), Win7SP1x86"
    #suggestedProfileList = suggestedProfileLine.replace("Suggested Profile(s) :","").split(",")     
            
    print "suggestedProfileList" + str(suggestedProfileList)
    print "suggestedProfileLine" + suggestedProfileLine
    print "imageType" + imageType
    
    servicePack = "SP" + imageType[-1]
    print "servicePack: " + servicePack

    suggestedProfiles = []
    # [' Win7SP1x86_23418, Win7SP0x86, Win7SP1x86']

    for suggestedProfile in suggestedProfileList:
    
        if "(" in suggestedProfile:
            print "it has a crappy comment!!"
            correctedProfile = suggestedProfile.strip()[0:suggestedProfile.find("(")-2]
            suggestedProfiles.append(correctedProfile)
        else:
            suggestedProfiles.append(suggestedProfile.strip())
        
    print suggestedProfiles

    print "Trying to determine profile based on pslist output."

    workingProfiles = []
    for suggestedProfile in suggestedProfiles:
        print "Trying profile: " + suggestedProfile
        command =  volatility_path + " -f "+memoryDump+ " --profile="+suggestedProfile+" pslist"
        print command
        output = subprocess.check_output(command, shell=True).decode('ascii', 'ignore')

        if not "No suitable address space mapping found" in output:
            workingProfiles.append(suggestedProfile)
            print "Good profile: " + suggestedProfile + " \n"
        else:
            print "Bad profile: " + suggestedProfile + " \n"
       
    print "\nIt was possible to parse pslist with the following profiles"
    for workingProfile in workingProfiles:
        print workingProfile
       
    workingProfileList = []   
    print "\nLooking for profiles matching Service Pack:"
    for workingProfile in workingProfiles:
        if servicePack in workingProfile:
            workingProfileList.append( workingProfile )
            
    if len(workingProfileList) > 1:
        print "several profiles matching service pack found"
        
        print "Trying to determine profile based on psscan output."

        workingProfiles2 = []
        for workingProfile in workingProfileList:
            print "Trying profile: " + workingProfile
            command =  volatility_path + " -f "+memoryDump+ " --profile="+workingProfile+" psscan"
            print command
            output = subprocess.check_output(command, shell=True).decode('ascii', 'ignore').split("\n")

            print "checking profile: " + workingProfile + " " + str(len(output))
            
            if len(output) > 3:
                Profile = workingProfile
                print "optimal profile: " + Profile
            else:
                print "Bad profile: " + suggestedProfile + " \n"
       
    
        
    else:
        Profile = workingProfileList[0]
        print "optimal profile: " + Profile
    
# Running plugins
def processPlugins(pluginSet):
    GlobalStartAnalysis = time.time()
    print "Running plugins..."
    for plugin in pluginSet:
            flog = open(logFile,"a")
            enabledProfiles = plugin[1].split("-")
            
            if (Profile in enabledProfiles or plugin[1] == "all") and  plugin[2] == 1 :
                print "\nRunning: "+plugin[0] +" "+plugin[3]+" plugin, please wait..."
                try:
                    pluginStartTime = time.time()
                    if len(plugin) == 6:
                        # If length is 6, a dumping plugin was provided, so the command will include the parameters to specificy output flag and value

                        outputDumpFolder = workingFolder + plugin[5]
                        if not (os.path.isdir(outputDumpFolder)):
                            os.makedirs(outputDumpFolder)
                        
                        command =  volatility_path + " -f "+memoryDump+ " --profile="+Profile+" "+plugin[0]+" "+plugin[3] + " "+plugin[4]+ " " +outputDumpFolder
                        output = subprocess.check_output(command, shell=True).decode('ascii', 'ignore')
                    else:
                        command = volatility_path + " -f "+memoryDump+ " --profile="+Profile+" "+plugin[0]+" "+plugin[3]
                        output = subprocess.check_output(command, shell=True).decode('ascii', 'ignore')
                        print output
        
                    pluginEndTime = time.time()
                    print "command: " + command
                    flog.write("command: " + command + "\n")
                    array = output.splitlines()
                        
                    with open(workingFolder+plugin[0] +".txt", 'a') as f:
                        f.write(output)
                        
                    print "plugin " + plugin[0] + " time: " + str(pluginEndTime - pluginStartTime)
                    flog.write("plugin " + plugin[0] + " time: " + str(pluginEndTime - pluginStartTime) + "\n\n")
                    
                except Exception,e:
                    exceptionMessage = "Exception generated while running plugin " + plugin[0] + " exception: " + str(e) + "\n\n"
                    print exceptionMessage
                    flog.write(exceptionMessage)
                    flog.close()
                
    GlobalEndAnalysis = time.time()
    print "Total time for analysis plugins: " + str(GlobalEndAnalysis - GlobalStartAnalysis)
    flog = open(logFile,"a")
    flog.write("Total time for analysis plugins: " + str(GlobalEndAnalysis - GlobalStartAnalysis))
    flog.close()

processPlugins(analysisPlugins)
flog.close()
