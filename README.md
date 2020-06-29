# fvol

Fast volatility script (fvol) is a wrapper script that will run volatility plugins against a memory dump and will save the output to a specific folder for later analysis. The output files are generated as every plugin runs so the analyst does not have to wait for the script to fully execute to start analysing the information. The script will also run the dumping plugins (procdump,malfind,moddump,dumpfiles,etc.) that will allow to analyze the retrieved files using various techniques. Every command is stored on the audit.txt file including the total execution time and the execution time of each plugin, which will help the analyst decide which plugins to enable and which ones should be executed first. If you know the profile of the memory dump, you can provide it, if not the script will try to determine it based on imageinfo output.

The intention of this script is to reduce the time waiting for volatility commands to complete, now if you receive a memory dump at the end of the day or before lunch you can leave it running and come back to analyze the output. 


TODO:
Flagging abnormal behavior of well-known Windows processes, based on the SANS Poster known evil. 
Calculating hash values of the dumped files and submitting hashes to Virus Total automatically using an API key to find known evil. 
Scanning the memory dump using a collection of memory based YARA rules. 
Scanning the dumped files with a collection of YARA rules. 
Compare the output against a known-good memory dump baseline
