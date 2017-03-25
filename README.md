TriFlow: Triaging Android Applications using Speculative Information Flows
---------------------------------------------------------------------------------------------------

VERSION:
------------

Version (by release date): 2017-02-15

DEVELOPER INFORMATION:
------------------------------------

Name: Omid Mirzaei <br />
Laboratory: Computer Security Lab (COSEC) <br />
University: Universidad Carlos III de Madrid <br />
Website: http://www.seg.inf.uc3m.es/~omirzaei/ <br />

PUBLICATION:
------------------

TriFlow: Triaging Android Applications using Speculative Information Flows
O. Mirzaei, G. Suarez-Tangil, J. E. Tapiador, J. M. de Fuentes
ACM Asia Conference on Computer and Communications Security (ASIACCS), Abu Dhabi, UAE (May 2017)

INSTALLATION INSTRUCTIONS:
----------------------------------------

Before using TriFlow, you only need to install python 2.7.11 on your system successfully. Moreover, you might need to install some python modules which are not commonly included in the regular installation of python and have been used in our scripts.

USAGE:
---------

TriFlow comes with two main modules which are Train_TriFlow and Score_TriFlow. The former one is used to train the system and to produce probabilities and weights of information flows from the dataset (dataset is an arbitrary directory which consists of 4 main sub-folders, i.e. Benign_Apks, Malware_Apks, Benign_Flows, and Malware_Flows), while the latter is used to score new unseen applications. For more information, we would like to refer you to our publication in AsiaCCS’17, and, also, the flowcharts on this repository.

To train TriFlow, you need to transfer the required files to four sub-folders explained above, and, then, running the below command in terminal:

python   Train_TriFlow   –i   ‘/Directory/of/Your/Dataset’   -o   ‘/Your/Desired/Output/Directory’

Once the above command is terminated, you will have two tables namely “Prob_InfoFlows_Sorted.csv” and “Weights_InfoFlows_Sorted.csv” in your desired output directory. Moreover, you will have two additional tables, “Freq_InfoFlows_Malware.csv” and “Freq_InfoFlows_Benign.csv”, which contain the frequencies of information flows in malwares and benign applications.

To score new applications based on the trained model, you need to copy all your applications in an arbitrary directory, and, then, running the below command in terminal:

python   Score_TriFlow   -a   ‘/Directory/of/Your/Applications’   -t   ‘/Directory/of/ProbabilityAndWeight/Tables’   -o   ‘/Your/Desired/Output/Directory

Once the above command is terminated, you will have two files in your desired output directory. The first one is “Sorted_Scores.csv” and contains all the scores for new applications, while the second one is “Scores_Percent.txt” that provides you with a detailed explanation of scores and the contribution of flows in each score. 

COPYRIGHT NOTICE:
--------------------------

All rights reserved for the above authors and research center. Please, look at the "License.txt" file for more detailed information regarding the usage and distribution of these source codes.

ACKNOWLEDGEMENT:
-----------------------------

This work was supported by the MINECO grant TIN2013-46469-R (SPINY: Security and Privacy in the Internet of You); by the CAM grant S2013/ICE-3095 (CIBER- DINE: Cybersecurity, Data, and Risks), and by the MINECO grant TIN2016-79095-C2-2-R (SMOG-DEV - Security Mechanisms for Fog Computing: Advanced Security for Devices)

NEWS:
---------

You can follow all updates and news either from my Twitter account or my home page listed below:

https://twitter.com/O_Mirzaei <br />
http://www.seg.inf.uc3m.es/~omirzaei/triflow.html
