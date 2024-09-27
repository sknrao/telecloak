UTD Anoymization toolbox requires java run time environment(JRE) 1.5 or higher.

In Windows systems, to run anonymizatin methods provided by toolbox, double-click the "anonymization.bat" script 
after adjusting the "config.xml" that is located in the toolbox main directory  according to requirements such as 
the anoymization method to be used, method parameters, input and output file locations and formats, etc... 
The details of the config.xml file is explaind at "UTD Anonymization ToolBox manual". 
A sample config.xml file is provided in the toolbox main directory (Sample config.xml represents a configuration for 
applying Datafly anamoymization method with k=10 on census data that is provided in the "dataset" sudirectory 
of the toolbox directory).

In Unix systems, open a terminal and change directory to the toolbox main directory and run the "anonymization.sh" script 
after adjusting the config.xml file as described above.

In addition to anonymization methods, toolbox provides implementation of two classicitation algorithms for classiying anonymous 
data that are SVM and IB1 respectively. In toolbox main directory scripts are provided to run these methods that are "SVManon.bat, 
IB1anon.bat"  for Windows systems and "SVManon.sh, IB1anon.sh" for Unix systems respectively. The input file format for applying 
these methods is Weka data format(ARFF). (A sample input file is provided in the "dataset" subdirectory of the main toolbox directory 
namely "header.txt"). In order to run these methods, the inputfilepath part in the scripts should be modified. Simply change the 
-arff "inputFilePath" part with your input file path and run the script.


Toolbox contains embedded sqlite database. Sqlite is not platform independent, it may require recompilation according to your platform. 
After running scripts, if they give arhitecture related problems, you may need to compile sqlite driver on your platform. 
For compilation, follow the steps given at http://www.ch-werner.de/javasqlite/overview-summary.html. After driver compilation, 
replace the sqlite native library and sqlite.jar in the toolbox directory with the new ones.  
