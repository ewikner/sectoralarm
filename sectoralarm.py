# -*- coding: utf-8 -*-
import datetime
import json
from helpers.HTML import parseHTMLToken, parseHTMLstatus, parseHTMLlog
import HTMLParser
import os
import re
import requests
import sys
import paho.mqtt.client as mqtt


LOGINPAGE = 'https://minasidor.sectoralarm.se/Users/Account/LogOn'
VALIDATEPAGE = 'https://minasidor.sectoralarm.se/MyPages.LogOn/Account/ValidateUser'
STATUSPAGE = 'https://minasidor.sectoralarm.se/MyPages/Overview/Panel/'
LOGPAGE = 'https://minasidor.sectoralarm.se/MyPages/Panel/AlarmSystem/'
COOKIEFILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'cookies.jar')

DATENORMRE = re.compile(r'(\d+)/(\d+) (\d+):(\d+)')
DATESPECRE = re.compile(r'^(.+) (\d+):(\d+)')

def create_mqtt_client():
    print 'create client'
    client = mqtt.Client()
    client.on_connect = on_mqtt_connect
    client.on_message = on_mqtt_message
    client.username_pw_set(config.MQTT_USERNAME, password=config.MQTT_PASSWORD)
    client.connect(config.MQTT_HOST, config.MQTT_PORT, 5)
    client.loop_forever()

    return client

def on_mqtt_connect(client, userdata, rc):
    print('Connected - Starting to process data.')
    client.subscribe('domoticz/out')
    client.publish('domoticz/in', ('{"command":"getdeviceinfo","idx":%s}' % (config.DOMOTICZ_IDX_ARMSTATE)))

def on_mqtt_message(client, userdata, msg):
    topic = msg.topic
    parsed_json = json.loads(msg.payload)
    idx = int(parsed_json['idx'])
    #print(parsed_json)

    if idx == int(config.DOMOTICZ_IDX_ARMSTATE):
        c_value = parsed_json['svalue1']
        print json.dumps(SECTORSTATUS.status(client, c_value))

def log(message):
    if os.environ.get('DEBUG'):
        print message


def fix_user(user_string):
    '''
    Cleanup the user string in the status object to only contain username.
    '''

    return user_string.replace('(av ', '').replace(')', '')


def fix_date(date_string):
    '''
    Convert the Sectore Alarm way of stating dates to something
    sane (ISO compliant).
    '''
    datematches = DATENORMRE.match(date_string)
    namematches = DATESPECRE.match(date_string)
    today = datetime.datetime.now().date()
    if datematches:
        the_date = datetime.datetime(
            int(datetime.datetime.now().strftime('%Y')),
            int(datematches.group(2)),
            int(datematches.group(1)),
            int(datematches.group(3)),
            int(datematches.group(4)))
        # If it's in the future, it was probably last year.
        if datetime.datetime.now() < the_date:
            the_date = datetime.datetime(
                the_date.year - 1,
                the_date.month,
                the_date.day,
                the_date.hour,
                the_date.minute)
    elif namematches:
        if namematches.group(1) == u'Idag':
            the_date = datetime.datetime(today.year, today.month, today.day)
        elif namematches.group(1) == u'Igår':
            the_date = (datetime.datetime(today.year,
                        today.month, today.day) - datetime.timedelta(1))
        else:
            raise Exception('Unknown date type in "{0}"'.format(date_string))

        the_date = the_date + datetime.timedelta(
            hours=int(namematches.group(2)),
            minutes=int(namematches.group(3)))

    else:
        raise Exception('No match for ', date_string)

    result = the_date.strftime('%Y-%m-%d %H:%M:%S')

    return result

class SectorStatus():
    '''
    The class that returns the current status of the alarm.
    '''

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()

    def __get_token(self):
        '''
        Do an initial request to get the CSRF-token from
        the login form.
        '''
        response = self.session.get(LOGINPAGE)
        parser = parseHTMLToken()
        parser.feed(response.text)

        if not parser.tokens[0]:
            raise Exception('Could not find CSRF-token.')

        return parser.tokens[0]

    def __get_status(self):
        '''
        Fetch and parse the actual alarm status page.
        '''
        response = self.session.get(STATUSPAGE + self.config.siteid)
        parser = parseHTMLstatus()
        parser.feed(response.text)
        return parser.statuses

    def __save_cookies(self):
        '''
        Store the cookie-jar on disk to avoid having to login
        each time the script is run.
        '''
        with open(COOKIEFILE, 'w') as cookie_file:
            json.dump(
                requests.utils.dict_from_cookiejar(self.session.cookies),
                cookie_file
            )
        log('Saved {0} cookie values'.format(
            len(requests.utils.dict_from_cookiejar(
                self.session.cookies).keys())))

    def __load_cookies(self):
        '''
        Load the cookies from the cookie-jar to avoid logging
        in again if the session still is valid.
        '''
        try:
            with open(COOKIEFILE, 'r') as cookie_file:
                self.session.cookies = requests.utils.cookiejar_from_dict(
                    json.load(cookie_file)
                )
        except IOError, e:
            if str(e)[:35] != '[Errno 2] No such file or directory':
                raise e

        log('Loaded {0} cookie values'.format(
            len(requests.utils.dict_from_cookiejar(
                self.session.cookies).keys())))

    def __is_logged_in(self):
        '''
        Check if we're logged in.

        Returns bool
        '''
        response = self.session.get(LOGINPAGE)
        loggedin = ('logOnForm' not in response.text)
        return loggedin

    def __login(self):
        '''
        Login to the site if we're not logged in already. First try any
        existing session from the stored cookie. If that fails we should
        login again.
        '''
        self.__load_cookies()

        if not self.__is_logged_in():
            log('Logging in')
            form_data = {
                'userNameOrEmail': self.config.email,
                'password': self.config.password
            }
            self.session = requests.Session()
            # Get CSRF-token and add it to the form data.
            form_data['__RequestVerificationToken'] = self.__get_token()

            # Verify username and password.
            verify_page = self.session.post(VALIDATEPAGE, data=form_data)
            if not verify_page.json()['Success']:
                print 'FAILURE',
                print (verify_page.json()['Message'] or 'No messsage')
                sys.exit(1)

            # Do the actual logging in.
            self.session.post(LOGINPAGE + '?Returnurl=~%2F', data=form_data)

            # Save the cookies to file.
            self.__save_cookies()
        else:
            log('Already logged in')

    def status(self, client, cvalue):
        '''
        Wrapper function for logging in and fetching the status
        of the alarm in one go that returns a dict.
        '''
        
        self.__login()

        # Get the status
        status = self.__get_status()
        status['timestamp'] = fix_date(status['timestamp'])
        status['user'] = fix_user(status['user'])
        current_alarm_status = status['event']
        #current_alarm_status = ''
        if cvalue != current_alarm_status:
            if current_alarm_status == u'Frånkopplat':
                alarm_code = 1;
                client.publish('domoticz/in', ('{"command":"udevice","idx":%s,"nvalue":%s,"svalue":"%s"}' % (self.config.DOMOTICZ_IDX_ARMSTATE, alarm_code, current_alarm_status)))
            elif current_alarm_status == u'Tillkopplat':
                alarm_code = 4;
                client.publish('domoticz/in', ('{"command":"udevice","idx":%s,"nvalue":%s,"svalue":"%s"}' % (self.config.DOMOTICZ_IDX_ARMSTATE, alarm_code, current_alarm_status)))
            else:
                alarm_code = 0;
                client.publish('domoticz/in', ('{"command":"udevice","idx":%s,"nvalue":%s,"svalue":"%s"}' % (self.config.DOMOTICZ_IDX_ARMSTATE, alarm_code, current_alarm_status)))

    client.loop_stop()
        client.disconnect()

        return status


if __name__ == '__main__':
    if len(sys.argv) < 2 or (sys.argv[1] != 'status' and sys.argv[1] != 'log'):
        print 'Usage: {0} [status|log]'.format(sys.argv[0])
        sys.exit(1)

    import config
    SECTORSTATUS = SectorStatus(config)
    
    mqtt_client = create_mqtt_client()
    # print json.dumps(SECTORSTATUS.status())