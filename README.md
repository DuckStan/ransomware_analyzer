# Ransomware analyzer

!!! PLEASE REVIEW THE CODE MANUALLY. THERE ARE LOTS OF CONFIGURATION DETAILS NOT MENTIONED IN THIS README !!!

Put suspicious files in the folder -> fire up the script -> see the results that might help you with further manual analysis

## How it works:

Ransomware analzyer works in three dimensions: static, dynamic and obfuscation analysis.

Static analysis:
- Analyzer counts the specific WinAPI functions by looking at the import table. If the numbers lie in anomaly range, it will raise the suspicion.

Dynamic analysis:
- Analyzer fires up the Windows Sandbox and shares the "sandbox folder". The sample file is executed and the dummy images are monitored. Analyzer looks for the following indicators of ransomware:
  1) Dummy images inside the folder have a different hash after the execution;
  2) There are files with extensions other than ".jpg", and ".png";
  3) There is a file with ".txt" extension (likely a ransomware note);

Obfuscation analysis:
- Analyzer estimates the entropy of a file and looks for the packed sections. Note that, however, commerical programs use these techniques as well.

## System requirements:

- Windows Sandbox installed and enabled (https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview);

- Python 3+ and dependencies (requirements.txt can help);

## Usage:

1) Install Detect It Easy in "Detect_It_Easy" folder;
2) Load some dummy images in "./sandbox_folder/images" and "./sandbox_folder/images_backup" folders;
3) Occupy your "samples" folder with the suspicious files for analysis;
4) Start up the main.py script and have a look at the analysis on each sample in "results folder";

# Personal Comments

Analyzer was mainly inspired by the DevSecOps process. In other words, it was meant to automate the analysis of suspicious files in a pipeline manner.

Though it may not compete with commercial products (mostly due to large signatures database), it does well at doing the behavioral analysis.

Since Windows Sandbox is not used as often, I hope that this project will pose as an example of its use. Though the sandbox itself indeed needs further improvements and a functional API (along with the hide convertd ).

Feel free to open an issue in case any suggestions and problems arise.
