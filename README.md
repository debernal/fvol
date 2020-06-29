# fvol

The intention of this script is that it will save the analysis some time of running volatility commands and will let them focus on the anlaysis of the information, now if you receive a memory dump at the end of the day or before lunch you can leave it running and come back to analyze the output. 

Wrapper script that will run volatility plugins against a memory dump and will save the output for later analysis. It will also measure the time required by every plugin to execute that will help you decide which ones to enable and which ones should be executed first. The output files will be generated after every plugin runs. It will also dump files, modules, running executables and registry hives. Every command run is stored on the audit.txt file. If you know the profile of the memory dump, you can provide it, if not the script will try to determine it based on imageinfo output.

TODO:
Flagging abnormal behavior of well-known Windows processes, based on the SANS Poster known evil. 
Calculating hash values of the dumped files and submitting hashes to Virus Total automatically using an API key to find known evil. 
Scanning the memory dump using a collection of memory based YARA rules. 
Scanning the dumped files with a collection of YARA rules. 
