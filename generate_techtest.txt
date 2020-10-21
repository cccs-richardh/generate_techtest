""" generate_techtest.py
    This script will parse through the index.yaml file from the Atomic Red Team
    test suite.
    Why, why, would we do this?
    Well, the index file (found in the ART repo here: atomic-red-team/atomics/Indexes/index.yaml)
    contains the full list of tests. This has technique/command line info.
    We can parse this info for just what we need (each time ART delivers a new version of ART)
    and produce the techniques_testnumber.py file that can be used by the atf_verifier.py script
    to identify the specifics of what our tradecraft has caught.

    So, this script needs the path to the index.yaml file and it will produce a candidate
    techniques_testnumber.py file for use by the verifier."""

import logging
import argparse
import sys
from pathlib import Path
import time
import yaml


# ========================================================
# GLOBALs
# ========================================================
#INDEX_FN = "ART/atomics/Indexes/index.yaml"
# this is the default INPUT file, containing the index of all of the ART tests
INDEX_FN = "example.index.yaml"
# this is the default OUTPUT file, it will contain a much leaner list of tuples
TECHNIQUE_TESTNUMBERS_FN = "CANDIDATE-techniques_testnumber.py"
# this is the list that we'll create during our parsing
TECHNIQUE_TESTNUMBERS_LIST = []
# this list should look like this:
#   [ (r"T1546.004-1",r'echo "#{command_to_add}" >> ~/.bash_profile'),
#     (r"T1546.004-2",r'echo "#{command_to_add}" >> ~/.bashrc') ]


# ========================================================
# HELPER FUNCTIONS
# ========================================================
def gather_cmdline_args():
    """ This function can be called in the main to gather up the command line arguments.
    :return: arg object with the gathered arguments
    """
    print("\nGathering command line arguments...")
    parser = argparse.ArgumentParser(description=__file__, add_help=True)
    parser.add_argument('-l', '--log_level', type=str,
                        help='Logging level. Choose from this list: [DEBUG, INFO, WARNING, ERROR, CRITICAL].',
                        required=True)
    parser.add_argument('-i', '--index_file', type=str,
                        help='The path to the index.yaml file that this script will parse.',
                        required=False)
    parser.add_argument('-o', '--output_file', type=str,
                        help='The path to the output file that this script will produce.',
                        required=False)
    args = parser.parse_args()
    print("\n  Command line args recd:")
    print("       log_level: {}".format(args.log_level))
    print("      index_file: {}".format(args.index_file))
    print("     output_file: {}".format(args.output_file))
    print("\n")
    return args

def check_logging(a_config):
    """ This function can be called in the main to do some validation of the
        logging argument passed in.
        This function will also configure the logging system with a format.
    :param a_config: an arg parser object
    :return: None.
    """
    #log_msg_format = '%(asctime)s [%(levelname)-5s] %(message)s (%(funcName)s:%(filename)s)'
    log_msg_format = '%(asctime)s [%(levelname)-5s] %(message)s'
    log_date_format = '%m/%d/%Y %I:%M:%S %p'
    logging_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    logging_levels_int = {'DEBUG': logging.DEBUG,
                          'INFO': logging.INFO,
                          'WARNING': logging.WARNING,
                          'ERROR': logging.ERROR,
                          'CRITICAL': logging.CRITICAL}

    # check to ensure that what the user has passed in a legit log level
    if a_config.log_level in logging_levels:
        logging_level = logging_levels_int[a_config.log_level]
    else:
        # default to the ERROR logging level
        logging_level = logging_levels_int['ERROR']
        print(f"An invalid logging level was passed:{a_config.log_level}. Defaulting to 'Error' level.")
    logging.basicConfig(format=log_msg_format, datefmt=log_date_format, level=logging_level)

def check_index_file(a_config):
    """ This function can be called in the main to do some validation of the
        index_file argument that might get passed in as an argument.
        This function will also populate the config if none has been passed.
    :param a_config: an arg parser object
    :return: None.
    """
    # has the user passed anything in?
    if not a_config.index_file:
        # if not, we'll use a global set above
        a_config.index_file = INDEX_FN
        logging.info(f"An index file has NOT been provided at the command line."
                     f"Setting the index filename to a local global value:"
                     f"{INDEX_FN}")
    else:
        # an index filename has been passed in
        if not Path(a_config.index_file).is_file():
            logging.error('Invalid index yaml file. Exiting.')
            sys.exit()
        else:
            logging.info(f"The {a_config.index_file} file exists, we'll parse it.")

def check_output_file(a_config):
    """ This function can be called in the main to do some validation of the
        output_file argument that might get passed in as an argument.
        This function will also populate the config if none has been passed.
    :param a_config: an arg parser object
    :return: None.
    """
    # has the user passed anything in?
    if not a_config.output_file:
        # if not, we'll use a global set above
        a_config.output_file = TECHNIQUE_TESTNUMBERS_FN
        logging.info(f"An output file has NOT been provided at the command line."
                     f"Setting the output filename to a local global value:"
                     f"{TECHNIQUE_TESTNUMBERS_FN}")

def begin_the_list(techtestlist):
    """ accept an empty list
        add to this list a set of lines that will be written when this list is serialized to disk"""
    techtestlist.append("TECHNIQUES_TESTNUMBERS = [\n")

def insert_to_list(techtestlist, techtest, uniquepattern):
    techtestlist.append(f"    (r\"{techtest}\",r\'{uniquepattern}\'),\n")

def end_the_list(techtestlist):
    techtestlist.append("]\n")

def write_out_list(techtestlist, techtestfn):
    with open(techtestfn,'w') as out_f:
        for line in techtestlist:
            out_f.write(line)


# ========================================================================================
# MAIN
# ========================================================================================
# Usage: python generate_techtest.py --log_level INFO --index_file example.index.yaml
# ========================================================================================
# Gather command line args
# =================================
config = gather_cmdline_args()
# Check the sanity of the command line args
# =================================
check_logging(config)
check_index_file(config)
check_output_file(config)
# Initialize the technique/testnumber list
# =================================
begin_the_list(TECHNIQUE_TESTNUMBERS_LIST)
# put in a small delay to clean up the print/logging output,
#   strictly for eye pleasure, can be removed in needed
time.sleep(2)

logging.info(f"========================== Beginning to parse the {config.index_file}.")
# Open up the index.yaml file
# =================================
with open(INDEX_FN, 'r', encoding='utf-8') as in_f:
    idx_generator = yaml.load_all(in_f, Loader=yaml.FullLoader)
    # get a doc (dict) from the index (yaml generator)
    #   there is probably only one doc in this yaml file though...
    #
    # Let's gather some stats about this file
    # =================================
    technique_counter = 0
    implemented_test_counter = 0
    manual_test_counter = 0
    # Loop though all yaml docs in this yaml file (probably only one)
    # =================================
    for doc_dict in idx_generator:
        for category, cat_dict in doc_dict.items():
            logging.info(f"Category: {category}")
            for technique, tech_dict in cat_dict.items():
                logging.info(f"  Technique: {technique}")
                technique_counter += 1
                for spec_tech, spec_list in tech_dict.items():
                    tests_within_tech_counter = 0
                    if 'technique' in spec_tech:
                        #logging.info("found the technique")
                        pass
                    else:
                        # this is the 'atomic_tests' part of this specific technique
                        for item in spec_list:
                            name = item.get('name')
                            if not name:
                                # Zero occurrences of this
                                logging.error("      No name found for this atomic test!")
                            executor = item.get('executor')
                            if not executor:
                                # Zero occurrences of this
                                logging.error("      No executor found for this atomic test!")
                            command = executor.get('command')
                            if not command:
                                # this can happen, 19 occurrences on sept 17 2020
                                # this probably means that this is a partially manual procedure
                                logging.error("      No command line found for this atomic test! Is this a manual test procedure?")
                                manual_test_counter += 1
                            if name:
                                logging.info(f"    name: {item['name']}")
                                tests_within_tech_counter += 1
                                implemented_test_counter += 1
                            if executor and command:
                                # find the first XX chars in the command line but only up to the end line
                                endline = command.find("\n")
                                if endline > 50:
                                    logging.info(f"    command line: {command[0:50]}")
                                    insert_to_list(TECHNIQUE_TESTNUMBERS_LIST,f"{technique}-{tests_within_tech_counter}",f"{command[0:50]}")
                                else:
                                    logging.info(f"    command line: {command[0:endline]}")
                                    insert_to_list(TECHNIQUE_TESTNUMBERS_LIST,f"{technique}-{tests_within_tech_counter}",f"{command[0:endline]}")
                            else:
                                    logging.error("    command line: None found.")
# Write out the resultant list
# =================================
end_the_list(TECHNIQUE_TESTNUMBERS_LIST)
write_out_list(TECHNIQUE_TESTNUMBERS_LIST,config.output_file)
# Log some interesting stats
# =================================
logging.info("")
logging.info(f"            Techniques found: {technique_counter}")
logging.info(f"Implemented test cases found: {implemented_test_counter}")
logging.info(f"Manual only test cases found: {manual_test_counter}")
logging.info(f"========================== Finished.")
