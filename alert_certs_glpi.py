#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
DESCRIPTION :
  * Sending mail when certificat is expired (GLPI).
  * 
  * 

  AUTHOR :
  * Samuel RONCIAUX <sronciaux@fr.scc.com>    START DATE :    Tue 2021 21 01 15:00 

  CHANGES :
  * VERSION     DATE        WHO                                         DETAIL
  * 0.0.1       2021-01-27  Samuel RONCIAUX <sronciaux@fr.scc.com>             Initial version
'''

__author__ = "Samuel, RONCIAUX"
__copyright__ = "2021, SCC"
__credits__ = ["Samuel, RONCIAUX"]
__license__ = "GPL"
__version__ = "0.0.1"
__maintainer__ = "Samuel RONCIAUX"

## MODULES FEATURES #######################################################################################################

# Import the following modules:
import sys, re, argparse, requests, urllib3
from pprint import PrettyPrinter
from datetime import datetime
import dateutil.parser
from dateutil.tz import tzlocal
import smtplib

pp = PrettyPrinter()

# If required, disable SSL Warning Logging for "requests" library:
urllib3.disable_warnings()


## Declare Functions ######################################################################################################
# Build a custom URL for GLPI to get a valid Session Token
def get_token(glpi_host, user_token, app_token):
    try:	
        # Create correct url to request
        # Create headers to authenticate
        headers = {
        "Content-Type": "application/json",
        "Authorization": "user_token " + user_token,
        "App-Token": app_token
        }

        # Request the URL and extract the token
        r = requests.get(
            "https://" + glpi_host + ":443/apirest.php/initSession",
            headers=headers,
            verify=False
        )

        return r.json()['session_token']

    except Exception as e:
        print("Error calling \"get_token\"... Exception {} --- Verify login, mdp or clientID !".format(e))
        sys.exit(3)

# Get All Certificats to retrieve validated date one by one
def get_certificat(glpi_host, session_token, app_token):
    try:

        # Create correct url to request
        # Create headers to authenticate
        headers = {
            "Content-Type": "application/json",
            "Session-Token": session_token,
            "App-Token": app_token
        }

        # Request the URL and return Certificate 
        r = requests.get(
            "https://" + glpi_host + ":443/apirest.php/Certificate",

            
            headers=headers,
            verify=False
        )

#Evaluate datetime expiration
        now = datetime.now()
        result = []
        for i in [
            {
                'id': i['id'],
                'name': i['name'],
                'id_tech_user': i['users_id_tech'],
                'date': i['date_expiration']

            } for i in r.json() if type(i['date_expiration']) == str
        ]: 
            #print (i['date'])
            expiration_cert = datetime.strptime(i['date'], '%Y-%m-%d')
            delta = now - expiration_cert
            #print ("date {} : {}".format(i['date'], delta.days))
            if delta.days > -28:
                result.append(i)

        return result

    except Exception as e:
            print("Error calling \"get_certificate\"... Exception {}".format(e))
            sys.exit(3)


def sendmail(sender, rcpt, cert_list):
    #Sending mail
    message = """
From: <{mail_from}>
To: <{mail_to}>
Subject: Alerte Expiration Certificat(s)

Voici la liste des certificats expirés et/ou arriavnt à expiration :
{cert_list}
    """.format(
            mail_from=sender,
            mail_to=rcpt,
            
            cert_list='\n'.join(["  - {} ({})".format(i['name'], i['date']) for i in cert_list])
        )

    try: 
        smtpObj = smtplib.SMTP('smtp.intranet.cg43.fr', 25)
        rc = smtpObj.sendmail(sender, rcpt, message.encode('utf8'))         
        print ("sendmail to '{}' returned {}".format(rcpt, rc)) 
    except smtplib.SMTPException as e:
        print("Error calling \"SMTPException\"... Exception {}".format(e))



# Get User Tech from id 
def get_usertech(glpi_host, session_token, app_token, userid):
    try:

        # Create correct url to request
        # Create headers to authenticate
        headers = {
            "Content-Type": "application/json",
            "Session-Token": session_token,
            "App-Token": app_token
        }

        # Request the URL and return mail adress 
        r = requests.get(
            "https://{}:443/apirest.php/user/{}/Useremail".format(glpi_host, userid),
            headers=headers,
            verify=False
        )
        if r.status_code == 200:
            return r.json()[0]['email']
        
    except Exception as e:
        print("Error calling \"get_usertech\"... Exception {}".format(e))
        sys.exit(3)

    return None




## Get Options/Arguments then Run Script ##################################################################################

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="""
            Glpi script to alert on certificats expiration.
            """,
            usage="""
    Evaluate certificat expiration on Glpi inventory and send mail to user that is responsible.

            python3 alert_certs_glpi.py -H <Host> -u <UserToken> -a <AppToken> 
            
            example : alert_certs_glpi.py -H localhost -u IXiUDoIEMzHkWVzVCg4M15EyVXI3OJoqDXbeognR 
            -a 5FIdwzbWzjfbEWsB6bW5HFELsC0cGO13zC9rYwt0
            
            """,
            epilog="version {}, copyright {}".format(__version__, __copyright__))
    parser.add_argument('-H', '--hostname', type=str, help='hostname or IP address', required=True)
    parser.add_argument('-u', '--usertoken', type=str, help='GLPI API User Token', required=True)
    parser.add_argument('-a', '--apptoken', type=str, help='GLPI API App Token', required=True)

    args = parser.parse_args()	
    
    # Authenticate and retreive session token
    session_token = get_token(args.hostname, args.usertoken, args.apptoken)

    #pp.pprint(cert_list)

    cert_list = []
    for i in get_certificat(args.hostname, session_token, args.apptoken):

        if i['id_tech_user'] not in [ i['user'] for i in cert_list]:
            cert_list.append(
                {
                    'user': i['id_tech_user'],
                    'email': get_usertech(args.hostname, session_token, args.apptoken, i['id_tech_user']),
                    'certs': [{'name': i['name'], 'date': i['date']}]
                }
            )
        else:
            for j in cert_list:
                if i['id_tech_user'] == j['user']:
                    j['certs'].append(
                        {
                            'name': i['name'],
                            'date': i['date']
                        }
                    )
                    break

    sender = 'glpi@hauteloire.fr'
    for i in cert_list:
        if i['email'] is None:
            continue
        sendmail(sender, i['email'], i['certs'])
