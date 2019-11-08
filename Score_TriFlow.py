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

This module scores applications based on the probabilities of information flows and their weights

ARGUMENTS:
---------

-a:     Directory of applications to be scored (.apk files)
-t:     Directory of probability and weight tables
-o:     Directory of applications' scores and the contributions of flows in the total scores

USAGE:
-----

python Score_TriFlow.py -a '/Directory/of/Applications' -t '/Directory/of/ProbabilityAndWeightTables' -o '/Directory/of/Scores'
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
if '-a' not in arguments or '-t' not in arguments or '-o' not in arguments:
    raise NameError('Error: input options are not provided')
else:
    # Directory of applications to be scored
    Apps_Dir = arguments[arguments.index('-a') + 1]
    # Directory of probability and weight tables
    Tables_Dir = arguments[arguments.index('-t') + 1]
    # Directory of applications' scores
    Output_Dir = arguments[arguments.index('-o') + 1]

Home_Dir = os.path.curdir											# Home directory

# ********************* End of Initialization *********************

# ********************* Main Body *********************

print('Scoring process started...')
#os.mkdir(os.path.join(Home_Dir,'Total_Flows_Apps'))
print('Extracting total information flows from applications...')
subprocess.call([sys.executable, os.path.join(Home_Dir,'Extract_Total_IFs.py'), '-i', Apps_Dir, '-o', os.path.join(Home_Dir,'Total_Flows_Apps')])
print('Scoring applications and preparing a detailed report...')
subprocess.call([sys.executable, os.path.join(Home_Dir,'Score.py'), '-f', os.path.join(Home_Dir,'Total_Flows_Apps/Flows'), '-t', Tables_Dir, '-o', Output_Dir])
# subprocess.call([sys.executable, os.path.join(Home_Dir,'Score_Normalized.py'), '-f', os.path.join(Home_Dir,'Total_Flows_Apps/Flows'), '-t', Tables_Dir, '-o', Output_Dir])

print('End of scoring!')

# ********************* End of Main Body *********************
