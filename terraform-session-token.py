#!/usr/bin/env python3
"""
A small AWS Multi Factor Authentication tool to create a session token
for an assumed role and updates the AWS credentials file for Terraform.
"""

import argparse
import configparser
from sys import stderr, exit as sysexit
from os import path
from shutil import copyfile
from uuid import uuid4
from boto3 import client, session
from botocore.exceptions import ClientError, NoCredentialsError, ParamValidationError
from colorama import Fore, Style

ARGPARSER = argparse.ArgumentParser(
    description='Generates a Session Token using a Role and MFA Device'
)
ARGPARSER.add_argument(
    "-d",
    type=int,
    default="3600",
    metavar="3600",
    help="duration the token is valid (sec)",
    required=False
)
ARGPARSER.add_argument(
    "-p",
    type=str,
    default="default",
    metavar="default",
    help="aws profile to use (Access & Secret)",
    required=False
)
ARGPARSER.add_argument(
    "-s",
    type=str,
    default=None,
    metavar="terraform_session",
    help="profile name for the Session Token to produce",
    required=False
)
ARGS = ARGPARSER.parse_args()

AWS_CONFIG_FILE = path.expanduser("~/.aws/config")
AWS_CREDENTIALS_FILE = path.expanduser("~/.aws/credentials")


def get_session_token(role, source_profile, mfa_serial, mfa_code):
    """
    Tries to get credentials via profile provided

    :return: ARN of the MFA device, and Username
    """
    try:
        global ARGS
        new_session = session.Session(profile_name=source_profile, )
        new_client = new_session.client('sts')
        credentials = new_client.assume_role(
            DurationSeconds=ARGS.d,
            RoleSessionName=ARGS.s,
            RoleArn=role,
            SerialNumber=mfa_serial,
            TokenCode=mfa_code
        )
    except ClientError as err:
        print("\n%s, Exiting" % err, file=stderr)
        sysexit(1)
    except NoCredentialsError as err:
        print("\n%s, Exiting" % err, file=stderr)
        sysexit(1)
    return credentials


def write_token(file, profile, token):
    """
    Creates a backup and Updates the Credentials file with a session token from STS

    :type file: string
    :param file: Credentials file name to be used

    :type profile: string
    :param profile: Title of the profile to be created or updated

    :type token: string
    :param token: The Session Token details
    """
    file_backup = file + ".bak"
    copyfile(file, file_backup)
    with open(file, "w") as out_file, open(file_backup, "r") as in_file:
        data_list = in_file.read().splitlines()
        access_key = "aws_access_key_id = " + \
            token['Credentials']['AccessKeyId']
        secret_key = "aws_secret_access_key = " + \
            token['Credentials']['SecretAccessKey']
        session_token = "aws_session_token = " + \
            token['Credentials']['SessionToken']
        if profile in data_list:
            print("\nUpdating the profile %s%s%s in the credentials file" %
                  (Fore.GREEN, profile, Style.RESET_ALL))
            profile_section = data_list.index(profile)
            data_list[profile_section + 1] = access_key
            data_list[profile_section + 2] = secret_key
            data_list[profile_section + 3] = session_token
        else:
            print("\nAdding the profile %s%s%s to the credentials file" %
                  (Fore.GREEN, profile, Style.RESET_ALL))
            data_list.append("")
            data_list.append(profile)
            data_list.append(access_key)
            data_list.append(secret_key)
            data_list.append(session_token)
            data_list.append("")
        out_file.write("\n".join(data_list))


def get_profile_details(file, profile):
    """
    Reads role arn from AWS AWS_CONFIG_FILE if exists

    :type file: string
    :param file: Credentials file name to be used

    :type profile: string
    :param profile: Title of the profile from which to read details
    """
    config = configparser.RawConfigParser()
    try:
        config.read('/home/dario/.aws/config')
        role = config.get('profile %s' % profile, 'role_arn')
        source_profile = config.get('profile %s' % profile, 'source_profile')
        mfa_serial = config.get('profile %s' % profile, 'mfa_serial')
        return role, source_profile, mfa_serial
    except configparser.NoSectionError as err:
        print('\nProfile %s does not exists in %s' % (profile, file))
        print("\n%s, Exiting" % err, file=stderr)
        sysexit(1)
    except configparser.NoOptionError:
        return None


def main():
    """
    Prompts for a series of details required to generate a session token
    """
    try:
        print("\nTerraform Session Token\n")
        if not ARGS.s:
            ARGS.s = 'tf-%s' % ARGS.p
        profile_configured_role, source_profile, mfa_serial = get_profile_details(
            AWS_CONFIG_FILE, ARGS.p)
        exit
        entered_role = None
        if profile_configured_role is None:
            entered_role = input("Role [%s%s%s] (enter for default): " % (
                Fore.YELLOW, profile_configured_role, Style.RESET_ALL))
        selected_role = entered_role if entered_role else profile_configured_role
        if selected_role == None:
            print("Role not selected, exiting")
            sysexit(1)
        print('Selected role is: %s%s%s' %
              (Fore.GREEN, selected_role, Style.RESET_ALL))
        mfa_code = input("\nMFA code [%s%s%s]: " %
                         (Fore.YELLOW, mfa_serial, Style.RESET_ALL))
        session_token = get_session_token(
            selected_role, source_profile, mfa_serial, mfa_code)
        tf_profile_name = ARGS.s
        write_token(AWS_CREDENTIALS_FILE,
                    '[%s]' % tf_profile_name, session_token)
        print("Completed.")
    except KeyboardInterrupt:
        print("\nKeyboard Interrupted, Exiting")
        sysexit(0)


if __name__ == "__main__":
    main()
