""" This script will contact the mitre site for group attack chain info (for example:
    what is the collection and flow of techniques used by APT4 to attack us).

    Usage:
    python generate_group_tests.py -g APT4 -i index.yaml

    Produces:
    A .txt file that contains a simple list of tests to run by the RunTests.ps1.

    Detail:
    Step 1 - obtain mitre ATT&CK group attack chain info for given group
    Step 2 - skim the given index file and find any tests that apply
    Step 3 - output this list, in order
"""
