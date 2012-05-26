import mechanize, re, urllib, json

class NajdiSiSms(object):
    base_url= "http://id.najdi.si/login"
    session_url= "http://www.najdi.si/auth/login.jsp?sms=1&target_url=http://www.najdi.si/index.jsp"

    def __init__(self):
        self.br= mechanize.Browser()
        self.br.set_handle_robots(False)
        self.loggedin= False
        self.session= None

    def _login(self, username, password):
        self.br.open(self.base_url)
        try:
            self.br.select_form(name="lgn")
        except:
            self.loggedin= True
            return False
        self.br["j_username"]=username
        self.br["j_password"]=password
        response =self.br.submit()

        self.br.open("http://www.najdi.si")
        self.loggedin= True

        return True

    def _get_session(self):
        response= self.br.open(self.session_url)
        match=re.search( 'sms_so_l_(\d+)', response.get_data() )
        if not match:
            return None
        return match.group(1)

    def _send_sms( self, session, prefix, number, data ):
        response= self.br.open("http://www.najdi.si/sms/smsController.jsp?sms_action=4&sms_so_ac_%s=%s&sms_so_l_%s=%s&myContacts=&sms_message_%s=%s" % (session, str(prefix), session, str(number), session, urllib.quote(str(data))) )

        data=json.loads(response.get_data())

        if data.has_key("msg_left") and data.has_key("msg_cnt"):
            self.msg_left= data["msg_left"]
            self.msg_cnt= data["msg_cnt"]
            return True

        return False

    def _parse_number( self, number ):
        number= str(number)
        if len(number)>9:
            return None
        if len(number)==6:
            return ("41", number)
        if len(number)==8:
            return ( number[0:2], number[2:8] )
        if len(number)==9:
            return (number[1:3], number[3:9])

        return None
    def send_sms( self, username, password, number, text ):
        if not self.loggedin:
            self._login(username, password)

        if not self.session:
            self.session= self._get_session()
            if not self.session:
                self._login(username, password)
                self._get_session()
                if not self.session:
                    return False

        number= self._parse_number(number)
        if not number:
            return False

        response= self._send_sms( self.session, number[0], number[1], text )
        if not response:
            self.session= self._get_session()
            if not self.session:
                self._login(username, password)
                self._get_session()
                if not self.session:
                    return False
            response= self._send_sms( self.session, number[0], number[1], text )
            if not response:
                return False

        return True



