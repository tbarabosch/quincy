# General

Quincy is a memory forensic tool that detects Host-Based Code Injection Attacks (HBCIAs) in memory dumps. This is the prototpye implementation of Quincy referenced in the paper "Quincy: Detecting Host-Based Code Injection Attacks in Memory Dumps" published at [DIMVA 2017](https://itsec.cs.uni-bonn.de/dimva2017/).
Its detection is based on various features that are extracted from a memory dump with the help of the [Volatility framework](http://www.volatilityfoundation.org) and it employs tree-based machine learning algorithms (CART, RandomForest, ExtraTrees, AdaBoost, GradientBoosting; all included in [scikit-learn](http://scikit-learn.org/stable/)) for decision making.

## Why Quincy?

There are several reasons why you might want to give Quincy a try:

- First open source machine learning approach to detect HBCIAs in memory dumps 
- Integration of other approaches (malfind, hollowfind) to compare results 
- Integration of VirusTotal to quickly scan suspicious memory areas
- Prefiltering of known memory areas (based on clean base image) to improve scanning performance
- Easily extendable (see Extending Quincy)

## Forks are welcomed!

Forks and comments are welcome! They will help to improve Quincy. In order to be maintainable, future commits will only focus on the latest Windows version, i.e. Windows 10.

Please note that this is a prototype implementation and not intented to be a super stable production system. The precomputed machine learning models may not work perfectly with your analysis VM. However, they are shipped with Quincy to lower the entry boundary. The best way to obtain near-optimal results is to create your own model based on your analysis environment. See the tools QuincyDataExtraction and QuincyLearn.

# Installation

## Dependencies

### General
Please install the following tools:

- [volatility](https://code.google.com/p/volatility/) (version 2.5)
- [mongodb](https://www.mongodb.com) (version 2.6.10)
- [VirtualBox](https://www.virtualbox.org) (version 5.0.10)
- [python](https://www.python.org/) (version 2.7.12)
- [genisoimage](https://wiki.debian.org/genisoimage) (version 1.1.11)

Newer version may also work.

### Python
For Python independencies use pip:
~~~
pip install -r requirements.txt
~~~

**Please note:** for Windows 10 memory dumps, you might have to install volatility from the [repository](https://github.com/volatilityfoundation/volatility) and [patch](https://github.com/volatilityfoundation/volatility/issues/268) it!

## Quincy

Quincy runs without any special installation. However, you have to ensure several things before first usage. 

If you would like to create your own Quincy models, then you need to setup virtual machines (VMs). Install at least one Windows VM with VirtualBox, e.g. XP, 7,8 or 10. Configure and harden VM as needed. Copy sample executer script _code/dump\_generation/util/autoexec.bat_ to the VM and execute it as Administrator. Take a snapshot of the VM. Quincy will utilize this snapshot as clean base to start samples.

Finally, Copy _QuincyConfig.py.example_ to _QuincyConfig.py_ and change values such as VM names and API keys to your needs.
~~~
cp -v ./code/QuincyConfig.py.example ./code/QuincyConfig.py
~~~
 
Now you are ready to use Quincy.

# Usage

## Model Creation

Quincy has several scripts in order to create models based on new data. However, it already comes with a set of pre-learnt models and users may use them for their first tests.
The workflow of learning a new model with Quincy is quite simple. First, memory dumps of malicious and benign programs have to be generated and the features have to be extracted from them (QuincyDataExtraction.py).
Then, this data can be used for learning and optimizing (tree-based) models (QuincyLearn.py). Later, memory dumps can be scanned with these models (QuincyScan.py, see next Section).

### Data generation and extraction (QuincyDataExtraction.py)

QuincyDataExtraction generates memory dumps and extracts features from them. It can create a groundtruth and add it to
the data such that it is labeled for the later machine learning stage.

~~~
usage: QuincyDataExtraction [-h] [-v] [-l LOGFILE]
                            os
                            {feedSamples,generateDumps,createGroundTruth,addGroundTruth,extractFeatures,exportRawData}
~~~

It has several modes that are listed in the following. Please note that each mode has its own set of options.

- feedSamples -> feeds samples to the database
- generateDumps -> generates memory dumps of fed samples
- extractFeatures -> extracts features from dumps, configure in QuincyConfig.py
- createGroundTruth -> creates a groundtruth based on scanning the dumps with yara signatures
- addGroundTruth -> if groundtruth already existend add them with this option
- exportRawData -> exports the labeled raw data as CSV

### Model learning (QuincyLearn.py)

QuincyLearn learns a (tree-based) machine learning model.

~~~
usage: QuincyLearn [-h] [-v]
                   [--classifier {DecisionTree,RandomForest,ExtraTrees,AdaBoost,GradientBoosting}]
                   [--feature_selection]
                   csv model_name model_outpath
~~~

It expects a CSV file generated by QuincyDataExtraction, a name for the model, a path to store the model and one of the
five available classifiers (specified via --classifier). If needed, an optional feature selection (--feature_selection) can be conducted before
learning the model.

## HBCIA Detection (QuincyScan.py)

The script QuincyScan.py detects HBCIAs in memory dumps.

~~~
usage: QuincyScan [-h] [--custom_model CUSTOM_MODEL] [-v] [--with_malfind]
                  [--with_hollowfind] [--with_virustotal] [-vp PROFILE]
                  dump
~~~

It expects at least a memory dump as input. In addition, a custom model and a Volatiltiy profile can be handed over.
The model and the profile have to target the same Windows version. If no profile is handed over, QuincyScan tries to deduce
a suitable profile.

QuincyScan offers the option to compare the results of it directly to the results of Volatility's [malfind](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal)
and [hollowfind](https://github.com/monnappa22/HollowFind) as a reference. Furthermore, the VADs that QuincyScan supposes to be malicious can be uploaded to [virustotal](https://www.virustotal.com)
and checked against many antivirus-scanners in order to get a first hint towards the malware family. You need a [virustotal api key](https://www.virustotal.com/de/documentation/public-api/).

### Creation of prefilter map

QuincyScan allows prefiltering of known VADs, similar to HashTest. However, instead of using fuzzy hashing, it employs currently sha256 hashes to prefilter known VADs. The motivation is that hooking might only slightly change the fuzzy hash of a system library. 
Hence, QuincyScan relies on exact sha256 hashes. Prefiltering is especially interesting for malware analysts, who always start their analysis based on a clean image. They can create a prefilter map of a memory dump of the clean image and apply it later to the infected memory dump 

To create a prefilter map, use QuincyCreatePrefilter.py:

~~~
usage: QuincyCreatePrefilter [-h] [-v] [-vp PROFILE] clean_dump
~~~

To apply a prefilter map to a memory dump, hand over the map to QuincyScan with the option --prefilter.

# Extending Quincy

There are several ways to enhance Quincy. Just to name one: you could add/remove features. But there are more things to enhance, but these two are the most obvious things to enhance. Feel free to contribute to the repo!

## Features

The core of Quincy are its features. As time of writing, there are almost 40 of them. 

### Remove features

To remove features from Quincy, you just have to comment them out in your QuincyConfig.py Quincy will not consider them in the future. Be aware that this may break previously created models!

### Add features

Features are just Python files in the subfolder code/features, e.g. code_functions.py or memory_threads.py. They must contain a function called scan:

~~~
def scan(Scanner):
~~~
This function takes as input a Scanner object that provides you access to processes and VADs. It is expected to enumerate all processes and their VADs and compute something for the VADs A typically feature may look like the feature memory_network_strings.py:

~~~
import yara
import os

def scan(Scanner):
    p = os.path.join(os.path.split(os.path.realpath(__file__))[0], 'yara/network_strings.yar')
    rules = yara.compile(filepath=p)
    output = {}
    for process in Scanner.processes:
        output[str(process.Id)] = scan_vads(process, rules)
    return output

def scan_vads(process, rules):
    res = {}
    for vad in process.VADs:
        name = hex(vad.Start)[:-1] + "_" + hex(vad.End)[:-1]
        data = vad.read()
        matches = rules.match(data=data)
        res[name] = int(len(matches) > 0)
    return res
~~~
The function scan enumerates all processes and asks the function scan_vads to scan each VAD for network vocabulary. The function scan must return a nested dictionary with the results. The first layer represents the processes. The keys are the string representation of the process ID.
The second layer represents the VADs of a process and their results. The keys encode the VAD start and end address, e.g. 0x400000_0x4200000. The values is the result of the features computation.

After implementing the feature, you have to import it in your QuincyConfig.py to make it visible to Quincy. 
