# ************************ General Information ************************
'''
VERSION:
-------

Version (by release date): 2017-02-15

DEVELOPER INFORMATION:
---------------------

Name: Omid Mirzaei
Laboratory: Computer Security Lab (COSEC)
University: Universidad Carlos III de Madrid
Website: http://www.seg.inf.uc3m.es/~omirzaei/

PUBLICATION:
-----------

TriFlow: Triaging Android Applications using Speculative Information Flows
O. Mirzaei, G. Suarez-Tangil, J. E. Tapiador, J. M. de Fuentes
ACM Asia Conference on Computer and Communications Security (ASIACCS), Abu Dhabi, UAE (May 2017)

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

This module calculates the weights of all real information flows based on their frequencies in malwares and benign applications.

ARGUMENTS:
---------

-i:     Directory of applications (.apk files)
-o:     Directory of total sources and sinks extracted from applications (.txt files)

USAGE:
-----

python Extract_Total_SrcsSnks.py -i '/Directory/of/Applications' -o '/Directory/of/SourcesAndSinks'
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import shutil
import glob
import zipfile
import subprocess
import pickle
import sys

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

arguments = sys.argv
if '-i' not in arguments  or '-o' not in arguments:
    raise NameError('Error: input options are not provided')
else:
    # Directory of applications (.apk files)
    Input_Dir = arguments[arguments.index('-i') + 1]
    # Directory of total sources and sinks extracted from each application
    Output_Dir = arguments[arguments.index('-o') + 1]

# Home directory
Home_Dir = os.path.curdir

# Dictionary of SuSi source API methods in smali format
Dict_Srcs_Smali = {}
# Dictionary of SuSi sink API methods in smali format
Dict_Snks_Smali = {}                         

num_src = 0
with open(os.path.join(Home_Dir,'Sources_Smali.txt')) as src_txt:
    for line in src_txt:
        line = line.strip()
        Dict_Srcs_Smali[line] = num_src + 1
        num_src += 1

num_snk = 0
with open(os.path.join(Home_Dir,'Sinks_Smali.txt')) as snk_txt:
    for line in snk_txt:
        line = line.strip()
        Dict_Snks_Smali[line] = num_snk + 1
        num_snk += 1

# ********************* End of Initialization *********************

# ********************* Functions *********************

def Unpack(app):
    # ********************** Removing Smali_Files and Unzipped_App folders if they already exist **********************
    if 'Smali_Files' in os.listdir(Input_Dir):
        shutil.rmtree(os.path.join(Input_Dir,'Smali_Files'))
    if 'Unzipped_App' in os.listdir(Input_Dir):
        shutil.rmtree(os.path.join(Input_Dir,'Unzipped_App'))
    # ********************** End of Removing Smali_Files and Unzipped_App folders if they already exist **********************
    # ********************** Unzipping the application (.apk file) **********************
    os.mkdir(os.path.join(Input_Dir,'Unzipped_App'))
    with zipfile.ZipFile(app,"r") as zip_ref:
        zip_ref.extractall(os.path.join(Input_Dir,'Unzipped_App'))
    # ********************** End of Unzipping the application (.apk file) **********************
    # ********************** Disassembling the classes.dex file within the unzipped folder into Smali_Files folder **********************
    os.mkdir(os.path.join(Input_Dir,'Smali_Files'))
    subprocess.call(['java', '-jar', os.path.join(Home_Dir,'baksmali.jar'), '-o', os.path.join(Input_Dir,'Smali_Files'), os.path.join(Input_Dir,'Unzipped_App','classes.dex')])
    # ********************** End of Disassembling the classes.dex file within the unzipped folder **********************

# ********************* End of Functions *********************

# ************************ Creating the Super Set ************************

# Counting the total number of sources
with open(os.path.join(Home_Dir,"Sources_Smali.txt")) as myfile:
    num_src_method = sum(1 for line in myfile)
# Counting the total number of sinks
with open(os.path.join(Home_Dir,"Sinks_Smali.txt")) as myfile:
    num_snk_method = sum(1 for line in myfile)

# ********************* End of Creating the Super Set *********************

# ********************* Main Body *********************

if not os.path.exists(Output_Dir):
    os.mkdir(Output_Dir)

for appfile in glob.iglob(os.path.join(Input_Dir, "*.apk")):

    # Creating matrices for storing the total sources and sinks found within the smali codes of an application (Note: The zero index is not used for the sake of facility)
    flag_srcs = [0 for x in range(num_src_method + 1)]
    flag_snks = [0 for x in range(num_snk_method + 1)]

    dirname,filename = os.path.split(appfile)

    if filename + '-Sources_Results.txt' not in os.listdir(os.path.join(Home_Dir,'Total_Srcs_Snks')) or filename + '-Sinks_Results.txt' not in os.listdir(os.path.join(Home_Dir,'Total_Srcs_Snks')):
        # Contains all the sources
        srcs_results = open(os.path.join(Home_Dir,'Total_Srcs_Snks',filename + '-Sources_Results.txt'),'wb')
        # Contains all the sinks
        snks_results = open(os.path.join(Home_Dir,'Total_Srcs_Snks',filename + '-Sinks_Results.txt'),'wb')
        Unpack(appfile)

        for (subdir,dir,files) in os.walk(os.path.join(Input_Dir,'Smali_Files')):
            for file in files:
                if '.smali' in file:
                    smali_file = open(os.path.join(subdir,file),'rb')
                    for line in smali_file:
                        if ';->' in line:
                            for keys in Dict_Srcs_Smali:
                                if keys in line and flag_srcs[Dict_Srcs_Smali[keys]] == 0:
                                    flag_srcs[Dict_Srcs_Smali[keys]] = 1
                                    break
                            for keys in Dict_Snks_Smali:
                                if keys in line and flag_snks[Dict_Snks_Smali[keys]] == 0:
                                    flag_snks[Dict_Snks_Smali[keys]] = 1
                                    break

        pickle.dump(flag_srcs,srcs_results)
        pickle.dump(flag_snks,snks_results)
        srcs_results.close()
        snks_results.close()

        shutil.rmtree(os.path.join(Input_Dir,'Smali_Files'))
        shutil.rmtree(os.path.join(Input_Dir,'Unzipped_App'))

# ********************* End of Main Body *********************
