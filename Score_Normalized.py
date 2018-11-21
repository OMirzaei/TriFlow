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

This module scores applications based on the probabilities of information flows and their weights. Scores can be normalized to a specific ranges using new_min and new_max variables.

ARGUMENTS:
---------

-f:     Directory of total information flows which are extracted from applications
-t:     Directory of probability and weight tables
-o:     Directory of applications' scores and the contributions of flows in the total scores

USAGE:
-----

python Score_Normalized.py -f '/Directory/of/TotalFlows' -t '/Directory/of/ProbabilityAndWeightTables' -o '/Directory/of/Scores'
'''
# ************************ End of Module Information  ************************

# ************************ Importing Modules ************************

import os
import shutil
import csv
import glob
import ast
from collections import OrderedDict
import math
import operator
import pickle
import sys

# ************************ End of Importing Modules ************************

# ************************ Initialization ************************

arguments = sys.argv
if '-f' not in arguments or '-t' not in arguments or '-o' not in arguments:
    raise NameError('Error: input options are not provided')
else:
    # Directory of total information flows
    Total_Flows_Dir = arguments[arguments.index('-f') + 1]
    # Directory of probability and weight tables
    Tables_Dir = arguments[arguments.index('-t') + 1]
    # Directory of probability table for all information flows
    Output_Dir = arguments[arguments.index('-o') + 1]

Home_Dir = os.path.curdir
Loc_SuSi_Cat = Home_Dir + '/SuSi'                               # Location of SuSi categories .txt files

# Calculating the number of applications for which we intend to estimate the score
num_apps = len([item for item in os.listdir(Total_Flows_Dir) if '.txt' in item])
# Creating a dictionary for storing score values
Scores = {}
Normalized_Scores = {}
new_min = 0.1                       # New minimum value for normalization (Note: apps with '0' score will not be provided with detailed report; thus, try to choose a non-zero minimum value.)
new_max = 1                         # New maximum value for normalization

Dict_Srcs_Nat = {}                                      # Dictionary of SuSi sources in natural format
Dict_Snks_Nat = {}                                      # Dictionary of SuSi sinks in natural format
Sources_Cat = {}                                        # Dictionary of SuSi sources categories
Sinks_Cat = {}                                          # Dictionary of SuSi sinks categories

num_src = 0
with open(os.path.join(Home_Dir,'Sources.txt')) as src_txt:
    for line in src_txt:
        line = line.strip()
        Dict_Srcs_Nat[num_src + 1] = line
        num_src += 1

num_snk = 0
with open(os.path.join(Home_Dir,'Sinks.txt')) as snk_txt:
    for line in snk_txt:
        line = line.strip()
        Dict_Snks_Nat[num_snk + 1] = line
        num_snk += 1

with open(os.path.join(Loc_SuSi_Cat,'SourcesCat.txt')) as src_txt:
    for line in src_txt:
        if '<' in line and '>' in line:
            src = line.split('>')[0]+'>'
            line = line.split(' ')
            for i in range(0,len(line)):
                if '(' in line[i] and ')' in line[i] and '>' not in line[i]:
                    cat = line[i].lstrip('(')
                    cat = cat.rstrip()
                    cat = cat.rstrip(')')
            Sources_Cat[src] = cat

with open(os.path.join(Loc_SuSi_Cat,'SinksCat.txt')) as snk_txt:
    for line in snk_txt:
        if '<' in line and '>' in line:
            snk = line.split('>')[0]+'>'
            line = line.split(' ')
            for i in range(0,len(line)):
                if '(' in line[i] and ')' in line[i] and '>' not in line[i]:
                    cat = line[i].lstrip('(')
                    cat = cat.rstrip()
                    cat = cat.rstrip(')')
            Sinks_Cat[snk] = cat

Cat_Src = ['UNIQUE_IDENTIFIER','LOCATION_INFORMATION','NETWORK_INFORMATION','ACCOUNT_INFORMATION','FILE_INFORMATION','BLUETOOTH_INFORMATION','DATABASE_INFORMATION','EMAIL','SYNCHRONIZATION_DATA','SMS_MMS','CONTACT_INFORMATION','CALENDAR_INFORMATION','SYSTEM_SETTINGS','IMAGE','BROWSER_INFORMATION','NFC','NO_CATEGORY']
Cat_Snk = ['LOCATION_INFORMATION','PHONE_CONNECTION','VOIP','PHONE_STATE','EMAIL','BLUETOOTH','ACCOUNT_SETTINGS','AUDIO','SYNCHRONIZATION_DATA','NETWORK','FILE','LOG','SMS_MMS','CONTACT_INFORMATION','CALENDAR_INFORMATION','SYSTEM_SETTINGS','BROWSER_INFORMATION','NFC','NO_CATEGORY']

# ********************* End of Initialization *********************

# ************************ Creating the Dictionary ************************

Dict_Prob = {}                  # Dictionary of information flows' probabilities
Dict_Weight = {}                # Dictionary of information flows' weights
Dict_Total = {}                 # Dictionary of information flows' probabilities and weights
with open(os.path.join(Tables_Dir,'Prob_InfoFlows_Sorted.csv')) as CSV_Prob:
    reader = csv.reader(CSV_Prob)
    reader.next()
    for row in reader:
        Dict_Prob[(row[0],row[1])] = row[2]
with open(os.path.join(Tables_Dir,'Weights_InfoFlows_Sorted.csv')) as CSV_Weights:
    reader = csv.reader(CSV_Weights)
    reader.next()
    for row in reader:
        Dict_Weight[(row[0],row[1])] = row[2]
for key,value in Dict_Prob.iteritems():
    if key in Dict_Weight:
        Dict_Total[key] = [Dict_Prob[key],Dict_Weight[key]]
    else:
        Dict_Total[key] = [Dict_Prob[key],'0']
for key,value in Dict_Weight.iteritems():
    if key not in Dict_Prob:
        Dict_Total[key] = ['0',Dict_Weight[key]]

# ************************ End of Creating the Dictionary ************************

# ************************ Functions ************************

def normalize(value,old_min,old_max,new_min,new_max):
    # Checks range
    if old_min == old_max:
        print "Warning: Zero input range"
        return None

    if new_min == new_max:
        print "Warning: Zero output range"
        return None

    # Checks reversed input range
    reverseInput = False
    oldMin = min(old_min, old_max)
    oldMax = max(old_min, old_max)
    if not oldMin == old_min:
        reverseInput = True

    # Checks reversed output range
    reverseOutput = False
    newMin = min(new_min, new_max)
    newMax = max(new_min, new_max)
    if not newMin == new_min :
        reverseOutput = True

    portion = (value-oldMin)*(newMax-newMin)/(oldMax-oldMin)
    if reverseInput:
        portion = (oldMax-value)*(newMax-newMin)/(oldMax-oldMin)

    result = portion + newMin
    if reverseOutput:
        result = newMax - portion

    return result

# ************************ End of Functions ************************

# ************************ Scoring and normalization ************************

if not os.path.exists(Output_Dir):
    os.mkdir(Output_Dir)

Output_File = open(os.path.join(Output_Dir,'Scores_Percent.txt'),'wb')

for file in glob.iglob(os.path.join(Total_Flows_Dir, "*.txt")):

    Score = 0.0
    src_name = ' '
    snk_name = ' '

    dirname,filename = os.path.split(file)

    # Counting the total number of sources and sinks within each app by looking through smali files
    total_flows = pickle.load(open(os.path.join(Total_Flows_Dir,filename),'rb'))

    num_flows = len(total_flows)

    # Updating the corresponding array based on the total number of sources and sinks in each app (for methods)
    for i in range(0,num_flows):
        # ************************ Calculating the score of application ************************
        src_name = str(Dict_Srcs_Nat[total_flows[i][0]]+'\n')
        snk_name = str(Dict_Snks_Nat[total_flows[i][1]]+'\n')
        if (src_name,snk_name) in Dict_Total:
            Score_IF = (ast.literal_eval(Dict_Total[(src_name,snk_name)][0]) * ast.literal_eval(Dict_Total[(src_name,snk_name)][1]))
            if Score_IF != 0.0:
                Score = Score + Score_IF

    # The below matrices are used for storing the name and score of each application (Zero index is not used)
    if num_flows != 0:
        Scores[filename] = float(Score) / num_flows
    else:
        Scores[filename] = float(Score)      # When Score and num_flows are both zero


old_min = min(Scores.values())
old_max = max(Scores.values())
for file in glob.iglob(os.path.join(Total_Flows_Dir, "*.txt")):

    Dict_Score_Cat = {}                     # A dictionary for storing the contribution of each category to the total score
    for i in range(0,len(Cat_Src)):
        for j in range(0,len(Cat_Snk)):
            Dict_Score_Cat[(Cat_Src[i],Cat_Snk[j])] = [0]

    src_name = ' '
    snk_name = ' '

    dirname,filename = os.path.split(file)

    # Counting the total number of sources and sinks within each app by looking through smali files
    total_flows = pickle.load(open(os.path.join(Total_Flows_Dir,filename),'rb'))

    num_flows = len(total_flows)

    # Updating the corresponding array based on the total number of sources and sinks in each app (for methods)
    for i in range(0,num_flows):
        # ************************ Calculating the score of application ************************
        src_name = str(Dict_Srcs_Nat[total_flows[i][0]]+'\n')
        snk_name = str(Dict_Snks_Nat[total_flows[i][1]]+'\n')
        if (src_name,snk_name) in Dict_Total:
            Score_IF = (ast.literal_eval(Dict_Total[(src_name,snk_name)][0]) * ast.literal_eval(Dict_Total[(src_name,snk_name)][1]))                                                                      #Contribution of each flow
            if Score_IF != 0.0:
                Dict_Score_Cat[(Sources_Cat[src_name.rstrip()],Sinks_Cat[snk_name.rstrip()])][0] = Dict_Score_Cat[(Sources_Cat[src_name.rstrip()],Sinks_Cat[snk_name.rstrip()])][0] + Score_IF                #Contribution of each category
                Dict_Score_Cat[(Sources_Cat[src_name.rstrip()],Sinks_Cat[snk_name.rstrip()])].append((src_name,snk_name,Score_IF))
        # ************************ End of Calculating the score of application ************************

    Normalized_Scores[filename] = normalize(Scores[filename],old_min,old_max,new_min,new_max)

    if '.apk' in filename:
        App_Name = filename[:-10]
    else:
        App_Name = filename[:-10] + '.apk'

    # ************************ Writing to output file ************************
    Output_File.write('================================================\n')
    Output_File.write('Application Name = ' + App_Name + '\n\n')
    Output_File.write('Total Score = ' + str(Normalized_Scores[filename]) + '\n')

    if Normalized_Scores[filename] == 0.0:
        Output_File.write('\n')
    else:
        Output_File.write('\n')
        Output_File.write('\n')

        Dict_Score_Cat = OrderedDict(sorted(Dict_Score_Cat.items(), key=lambda t: t[1], reverse = True))          # Sort the dictionary of categories

        for key_cat in Dict_Score_Cat:
            if Dict_Score_Cat[key_cat][0] != 0:
                old_score_cat = (Dict_Score_Cat[key_cat][0] / float(num_flows))
                new_score_cat = (Normalized_Scores[filename] * old_score_cat) / Scores[filename]
                percent = (new_score_cat / Normalized_Scores[filename]) * 100
                Output_File.write('[' + key_cat[0] + ', ' + key_cat[1] + ']' + ' = ' + str(new_score_cat) + ' (' + str(percent) + '% of the score' + ')\n')

                # A dictionary for storing the contribution of each information flow to the total score
                Dict_Score_IF = {}

                for i in range(1,len(Dict_Score_Cat[key_cat])):
                    Dict_Score_IF[(Dict_Score_Cat[key_cat][i][0],Dict_Score_Cat[key_cat][i][1])] = Dict_Score_Cat[key_cat][i][2]
                Dict_Score_IF = OrderedDict(sorted(Dict_Score_IF.items(), key=lambda t: t[1], reverse = True))          # Sort the dictionary of information flows

                for key_IF in Dict_Score_IF:
                    if Dict_Score_IF[key_IF] != 0:
                        old_score_IF = Dict_Score_IF[key_IF] / float(num_flows)
                        new_score_IF = (new_score_cat * old_score_IF) / old_score_cat
                        Output_File.write(key_IF[0].rstrip() + ', ' + key_IF[1].rstrip() + ', ' + str(new_score_IF))

                        Output_File.write('\n')
                Output_File.write('\n\n')
    # ************************ End of writing to output file ************************

# ************************ End of Scoring and normalization ************************


# ************************ Storing the results ************************

# ********************* Creating the table of scores based on information flows for methods *********************

# Creating the headers
with open(os.path.join(Output_Dir,'Scores.csv'), 'wb') as csvfile:
    a = csv.writer(csvfile)
    a.writerow(['Application']+['Score'])
    for key in Normalized_Scores.iterkeys():
        if '.apk' in key:
            App_Name = key[:-10]
        else:
            App_Name = key[:-10] + '.apk'
        a.writerow([App_Name]+[Normalized_Scores[key]])

# ****************** End of Creating the table of scores based on information flows for methods ******************

# ********************* Sorting the table of scores based on information flows for methods *********************

Unsorted_File =open(os.path.join(Output_Dir,'Scores.csv'), 'rb')
infile = csv.reader(Unsorted_File)
infields = infile.next()
Sorted_File = sorted(infile, key=lambda t: float(t[1]))
with open(os.path.join(Output_Dir,"Sorted_Scores.csv"),'wb') as csvfile:
    a = csv.writer(csvfile)
    a.writerow(infields)
    for row in Sorted_File:
        a.writerow(row)

# ********************* End of Sorting the table of scores based on information flows for methods *********************

os.remove(os.path.join(Output_Dir,'Scores.csv'))     #Removing the unsorted table of scores

# *********************** End of Storing the results ************************
