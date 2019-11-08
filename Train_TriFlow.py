# ************************ General Information ************************
'''
VERSION:
-------

Version (by release date): 2018-11-21

DEVELOPER INFORMATION:
---------------------

Name: Omid Mirzaei
Laboratory: Computer Security Lab (COSEC)
University: Universidad Carlos III de Madrid
Website: https://cosec.inf.uc3m.es/~omid-mirzaei/

PUBLICATION:
-----------

TriFlow: Triaging Android Applications using Speculative Information Flows
O. Mirzaei, G. Suarez-Tangil, J. E. Tapiador, J. M. de Fuentes
ACM Asia Conference on Computer and Communications Security (ASIACCS), Abu Dhabi, UAE (April 2017)

COPYRIGHT NOTICE:
----------------

All rights reserved for the above developer and research center.
Please, take a look at the "License.txt" file for more detailed information regarding the usage and distribution of these source codes.

ACKNOWLEDGEMENT:
---------------

This work was supported by the MINECO grant TIN2013-46469-R (SPINY: Security and Privacy in the Internet of You);
by the CAM grant S2013/ICE-3095 (CIBER- DINE: Cybersecurity, Data, and Risks), and
by the MINECO grant TIN2016-79095-C2-2-R (SMOG-DEV - Security Mechanisms for Fog Computing: Advanced Security for Devices)
'''
# ************************ End of General Information ************************

# ************************ Module Information ************************
'''
MAIN FUNCTIONALITY:
------------------

This module trains the TriFlow system, i.e. it creates probability and weight tables from a dataset of applications and their corresponding flows.

ARGUMENTS:
---------

-i:     Directory of dataset (This directory should contain 4 different sub-folders with these names: 1. Benign_Apks 2. Malware_Apks 3. Benign_Flows 4. Malware_Flows)
-o:     Directory of probability and weight tables

USAGE:
-----

python Train_TriFlow.py -i '/Directory/of/Dataset' -o '/Directory/of/ProbabilityAndWeightTables'
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import shutil
import subprocess
import sys

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

arguments = sys.argv
if '-i' not in arguments  or '-o' not in arguments:
    raise NameError('Error: input options are not provided')
else:
    # Directory of dataset
    Input_Dir = arguments[arguments.index('-i') + 1]
    # Directory of probability and weight tables
    Output_Dir = arguments[arguments.index('-o') + 1]

if os.path.basename(Output_Dir) not in os.listdir(os.path.curdir):
    os.mkdir(Output_Dir)

# Home directory
Home_Dir = os.path.curdir
# Directory of benign apps (.apk files)
BenignApps_Dir = Input_Dir + '/Benign_Apks'
# Directory of malware (.apk files)
Malwares_Dir = Input_Dir + '/Malware_Apks'
# Directory of flows extracted from benign apps (.txt files)
BenignFlows_Dir = Input_Dir + '/Benign_Flows'
# Directory of flows extracted from malware (.txt files)
MalwareFlows_Dir = Input_Dir + '/Malware_Flows'

# ********************* End of Initialization *********************

# ********************* Main Body *********************

print('Training process started...')
# Merges benign apps and malware
if not os.path.exists(os.path.join(Input_Dir,'All_Apks')) or len(os.listdir(os.path.join(Input_Dir,'All_Apks'))) == 0:
    os.mkdir(os.path.join(Input_Dir,'All_Apks'))
    for app in os.listdir(BenignApps_Dir):
        shutil.copy(os.path.join(BenignApps_Dir,app),os.path.join(Input_Dir,'All_Apks',app))
    for app in os.listdir(Malwares_Dir):
        shutil.copy(os.path.join(Malwares_Dir,app),os.path.join(Input_Dir,'All_Apks',app))

# Merges benign flows and the ones from malware
if not os.path.exists(os.path.join(Input_Dir,'All_Flows')) or len(os.listdir(os.path.join(Input_Dir,'All_Flows'))) == 0:
    os.mkdir(os.path.join(Input_Dir,'All_Flows'))
    for flow in os.listdir(BenignFlows_Dir):
        shutil.copy(os.path.join(BenignFlows_Dir,flow),os.path.join(Input_Dir,'All_Flows',flow))
    for flow in os.listdir(MalwareFlows_Dir):
        shutil.copy(os.path.join(MalwareFlows_Dir,flow),os.path.join(Input_Dir,'All_Flows',flow))

# Extracts real information flows from FlowDroid output files
print('Extracting real information flows from FlowDroid output files...')
subprocess.call([sys.executable, os.path.join(Home_Dir,'Extract_Real_IFs.py'), '-i', os.path.join(Input_Dir,'All_Flows'), '-o', os.path.join(Home_Dir,'Real_Flows')])
# Extracts total information flows
print('Extracting total information flows from applications...')
subprocess.call([sys.executable, os.path.join(Home_Dir,'Extract_Total_IFs.py'), '-i', os.path.join(Input_Dir,'All_Apks'), '-o', os.path.join(Home_Dir,'Total_Flows')])
# Calculates the probabilities of information flows
print('Calculating the probabilities of information flows...')
subprocess.call([sys.executable, os.path.join(Home_Dir,'Probability.py'), '-r', os.path.join(Home_Dir,'Real_Flows'), '-t', os.path.join(Home_Dir,'Total_Flows/Flows'), '-o', Output_Dir])
print('Probability table was created...')

# Separating real information flows of malware and benign applications
print('Separating real information flows of malware and benign applications...')
Real_Flows_Benign = os.path.join(Home_Dir,'Real_Flows_Benign')
if os.path.basename(Real_Flows_Benign) not in os.listdir(os.path.curdir):
    os.mkdir(Real_Flows_Benign)
for app in os.listdir(BenignApps_Dir):
    if '.apk' in app:
        shutil.copy(os.path.join(Home_Dir,'Real_Flows',app + '-realflows.txt'),os.path.join(Real_Flows_Benign, app + '-realflows.txt'))
Real_Flows_Malware = os.path.join(Home_Dir,'Real_Flows_Malware')
if os.path.basename(Real_Flows_Malware) not in os.listdir(os.path.curdir):
    os.mkdir(Real_Flows_Malware)
for app in os.listdir(Malwares_Dir):
    if '.apk' in app:
        shutil.copy(os.path.join(Home_Dir,'Real_Flows',app + '-realflows.txt'),os.path.join(Real_Flows_Malware, app + '-realflows.txt'))

# Calculates the frequencies of information flows in benign apps
print('Calculating the frequencies of information flows in benign applications...')
subprocess.call([sys.executable, os.path.join(Home_Dir,'Frequency.py'), '-i', Real_Flows_Benign, '-o', Output_Dir])
os.rename(os.path.join(Output_Dir,'Freq_InfoFlows_Sorted.csv'),os.path.join(Output_Dir,'Freq_InfoFlows_Benign.csv'))
print('Frequency table was created for benign applications...')
# Calculates the frequencies of information flows in malware
print('Calculating the frequencies of information flows in malicious applications...')
subprocess.call([sys.executable, os.path.join(Home_Dir,'Frequency.py'), '-i', Real_Flows_Malware, '-o', Output_Dir])
os.rename(os.path.join(Output_Dir,'Freq_InfoFlows_Sorted.csv'),os.path.join(Output_Dir,'Freq_InfoFlows_Malware.csv'))
print('Frequency table was created for malicious applications...')
# Calculates the weights of information flows
print('Calculating the weights of information flows...')
subprocess.call([sys.executable, os.path.join(Home_Dir,'Weighting.py'), '-i', Output_Dir, '-o', Output_Dir])
print('Weight table was created...')

print('End of Training!')

# ********************* End of Main Body *********************

