# Ransomware analyzer

Put suspicious files in the folder -> fire up the script -> see the results that might help you with manual analysis

## How it works:

Ransomware analzyer works in three dimensions: static, dynamic and obfuscation analysis.

Static analysis consits of 

## System requirements:

- Windows Sandbox installed and running (https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview);

- Python v.3 and dependencies;

- 

## Usage:

1) Install Detect It Easy in "Detect_It_Easy" folder;
1) Load some dummy images in "./sandbox_folder/images" and "./sandbox_folder/images_backup" folders; 
2) Occupy your "samples" folder with the suspicious files for analysis;
3) Start up the main.py script and have a look at the analysis on each sample in "results folder";
