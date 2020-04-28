#!/usr/bin/env python

import argparse
import sys
from datetime import datetime
from datetime import timedelta
import json
import os.path
import jwt
import requests

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return open(arg, 'r')  # return an open file handle


class JWTBuilder(object):
    def __init__(self, issuer_id, key_file, key_id):
        self.audience = 'appstoreconnect-v1'
        self.issuer_id = issuer_id
        self.key = key_file.read()
        self.key_id = key_id
    
    def build(self):
        expiration_time = (datetime.now() + timedelta(minutes=20)).timestamp()
        payload = {
            "iss": self.issuer_id,
            "exp": expiration_time,
            "aud": self.audience
        }
        encoded_jwt = jwt.encode(payload, self.key, algorithm='ES256', headers={
                                 'kid': self.key_id})
        return encoded_jwt


class CertificateSubcommandArgumentsParser(object):
    def __init__(self):
        parser = argparse.ArgumentParser(usage='''
appstoreconnect certificate list 
appstoreconnect certificate create
                  ''')
        parser.add_argument('command', help='Subcommand to run')
        args = parser.parse_args(sys.argv[2:3])
        if not hasattr(self, args.command):
            print('Unrecognized command')
            parser.print_help()
            exit(1)
        getattr(self, args.command)()

    def list(self):
        parser = argparse.ArgumentParser(
            description='List certificates',
            usage='''appstoreconnect certificate list -i ISSUER_ID -e KEY_ID -k KEY_FILE 

                Where parameters are:
                -i      ISSUER_ID
                -e      KEY_ID
                -k      KEY_FILE
                ''')
        parser.add_argument("-i", dest="issuer_id", nargs='?', const="issuer_id")
        parser.add_argument("-k", dest="key_file", required=True,
                    help="key file", metavar="FILE",
                    type=lambda x: is_valid_file(parser, x))
        parser.add_argument("-e", dest="key_id", nargs='?', const="key_id")
        args = parser.parse_args(sys.argv[3:])
        CertificateAPI(issuer_id=args.issuer_id, key_file=args.key_file, key_id=args.key_id).list()

    def create(self):
        parser = argparse.ArgumentParser(
            description='Create certificate',
            usage='''appstoreconnect certificate create -i ISSUER_ID -e KEY_ID -k KEY_FILE -c CSR_FILE

                Where parameters are:
                -i      ISSUER_ID
                -e      KEY_ID
                -k      KEY_FILE
                -c      CSR_FILE
                ''')
        parser.add_argument("-i", dest="issuer_id", nargs='?', const="issuer_id")
        parser.add_argument("-k", dest="key_file", required=True,
                    help="key file", metavar="FILE",
                    type=lambda x: is_valid_file(parser, x))
        parser.add_argument("-e", dest="key_id", nargs='?', const="key_id")
        parser.add_argument("-c", dest="csr_file", required=True,
                    help="key file", metavar="FILE",
                    type=lambda x: is_valid_file(parser, x))
        args = parser.parse_args(sys.argv[3:])
        CertificateAPI(issuer_id=args.issuer_id, key_file=args.key_file, key_id=args.key_id).create(csr_file=args.csr_file)


class CertificateAPI(object):
    url = "https://api.appstoreconnect.apple.com/v1/certificates" 

    def __init__(self, issuer_id, key_file, key_id):
        self.jwt_token = JWTBuilder(issuer_id, key_file, key_id).build()
        self.bearer_header_value = f'Bearer {self.jwt_token.decode("utf-8")}'

    def list(self): 
        headers = {'Authorization': self.bearer_header_value}
        r = requests.get(url = self.url, headers=headers, verify=False) 
        parsed = json.loads(r.content)
        print(json.dumps(parsed, indent=4, sort_keys=True))

    def create(self, csr_file):
        headers = {'Authorization': self.bearer_header_value,
                    'Content-Type': 'application/json'}
        csrContent = csr_file.read()

        createData = {
            "data":{
                "attributes":{
                    "certificateType":"IOS_DISTRIBUTION",
                    "csrContent":csrContent
                },
            "type":"certificates"
            }
        } 
        r = requests.post(url = self.url, data=json.dumps(createData), headers=headers, verify=False) 
        parsed = json.loads(r.content)
        print(json.dumps(parsed, indent=4, sort_keys=True))


class MainArgumentsParser(object):

    def __init__(self):
        parser = argparse.ArgumentParser(
            description='AppStoreConnect API client',
            usage='''appstoreconnect <command> [<args>]

                These are common AppStoreConnect commands used in various situations:
                certificate     Perform task with Certificates
                profiles        Perform task with Provision Profiles
                ''')
        parser.add_argument('command', help='Subcommand to run')
        # parse_args defaults to [1:] for args, but you need to
        # exclude the rest of the args too, or validation will fail
        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            print('Unrecognized command')
            parser.print_help()
            exit(1)
        # use dispatch pattern to invoke method with same name
        getattr(self, args.command)()

    def certificate(self):
        CertificateSubcommandArgumentsParser()

    def profiles(self):
        parser = argparse.ArgumentParser(
            description='Perform task with Provision Profiles')
        # NOT prefixing the argument with -- means it's not optional
        parser.add_argument('repository')
        args = parser.parse_args(sys.argv[2:])
        print('Running provision profile create=%s' % args.repository)


if __name__ == '__main__':
    MainArgumentsParser()
