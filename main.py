try:
	from PyQt5.QtGui import QIcon
	from PyQt5.QtCore import pyqtSlot
	from PyQt5 import *
	from PyQt5.QtCore import *
	from PyQt5.QtWidgets import * 
	from PyQt5.QtGui import * 
	from PyQt5 import QtWidgets

	from threading import *
	from threading import Thread
	from datetime import date
	from datetime import datetime
	import os
	import re
	import io
	import sys
	import time
	import base64
	import threading
	import requests, json, random, base64
except Exception:
	import os
	print("Trying to Install required modules ...\n")
	os.system('python -m pip install -r requirements.txt')
	exit()


# Settings ------------------
MOBILE_NO = ""
PASSWORD = ""
OUT = "aPlus_Downloads"		# Output folder name in your Downloads folder
# ---------------------------

DEVICE = 'd2cca9b0a3b83eb0'
TOKEN = ''
USER = ''
V_KEY = ''
V_HASH = ''
PLAY_LIST = ''
PLAY_LIST_KEY = ''
PLAY_LIST_HASH = ''
API = "https://api.apluseducation.lk"
User_Agent = "Dalvik/2.1.0 (Linux; U; Android 12; XXXXXX MIUI/V12.5.4.0.XXXXXX)"
session = requests.session()
session.headers.update({"User-Agent" : "Dart/2.10 (dart:io)"})
session.headers.update({"Content-Type" : "application/json; charset=utf-8"})
session.headers.update({"Accept-Encoding" : "gzip"})

class Login(QDialog):
	def __init__(self, parent=None):
		super(Login, self).__init__(parent)
		self.setWindowTitle("aPlus Login | thiwaK")
		pixmap = QtGui.QPixmap()
		pixmap.loadFromData(QtCore.QByteArray.fromBase64(b'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'))
		icon = QtGui.QIcon(pixmap)
		self.setWindowIcon(icon)
		self.resize(390,190)
		
		self.txtMobile = QLineEdit(self)
		self.txtPass = QLineEdit(self)
		self.btnLogin = QPushButton('Login', self)

		layout = QFormLayout(self)
		layout.addRow(QLabel("Mobile Number"), self.txtMobile)
		layout.addRow(QLabel("Password"), self.txtPass)
		layout.addRow(QLabel(""), self.btnLogin)
		self.setLayout(layout)

		self.btnLogin.clicked.connect(self.login)

	def login(self):
		global PASSWORD, MOBILE_NO
		
		if(len(self.txtMobile.text().strip())!=12):
			msg = QMessageBox()
			msg.setIcon(QMessageBox.Critical)
			msg.setWindowTitle("Login")
			msg.setText("Check your Mobile Number")
			x = msg.exec_()
			return
		else:
			MOBILE_NO = self.txtMobile.text().strip()

		if(len(self.txtPass.text().strip())==0):
			msg = QMessageBox()
			msg.setIcon(QMessageBox.Critical)
			msg.setWindowTitle("Login")
			msg.setText("Check your Password")
			x = msg.exec_()
			return
		else:
			PASSWORD = self.txtPass.text().strip()

		session.headers.update({"Authorization" : "Bearer"})
		data = r"""{"operationName":"LoginAdmin","variables":{"input":{"mobile":""" + '\"' + MOBILE_NO + '\"' + r""","password":""" + '\"' + PASSWORD + '\"' + r"""}},"query":"mutation LoginAdmin($input: UserLogIn) {loginStudent(input: $input) {\n      accessToken\n      userAccount {\n        _id\n        fname\n        lname\n        email\n        mobile\n        role\n        status\n        created_at\n        updated_at\n      }\n    }\n  }"}"""
		url = API + "/api/gql"

		r = session.request("POST", url, data=data)
		raw_response = r.text

		try:
			jsonData = json.loads(raw_response)
			TOKEN = jsonData["data"]["loginStudent"]["accessToken"]
			USER = jsonData["data"]["loginStudent"]["userAccount"]
			
			data = {}
			data['user'] = MOBILE_NO
			data['pass'] = PASSWORD
			json_data = json.dumps(data)
			
			print(json_data)

			with open("lib\\cred.inf", 'w') as f:
				f.write(json_data)

			msg = QMessageBox()
			msg.setIcon(QMessageBox.Information)
			msg.setWindowTitle("Login")
			msg.setText("Success !")
			x = msg.exec_()
			self.accept()

		except Exception as e:
			msg = QMessageBox()
			msg.setIcon(QMessageBox.Critical)
			msg.setWindowTitle("Login")
			msg.setText("Error Login. Try Again")
			x = msg.exec_()
			return

class aPlus(QWidget):

	def __init__(self,parent=None):
		super().__init__(parent)

		self.setWindowTitle("aPlus Downloader | thiwaK")
		# self.setWindowIcon(QtGui.QIcon('icon.png'))
		# self.icon = QtGui.QIcon()
		# self.icon.addPixmap(QtGui.QPixmap("icon.png"), QtGui.QIcon.Selected, QtGui.QIcon.On)
		pixmap = QtGui.QPixmap()
		pixmap.loadFromData(QtCore.QByteArray.fromBase64(b'iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAABmJLR0QA/wD/AP+gvaeTAAAGUElEQVR42u2afVBUVRTAsf5psnSyqUwlSxM/UD5CJUGRhRDFBIFQwOVTwERQS1ObkHAMR5vGpv6oP9BJTUfFVlA+/ABTFDNzMpumQqk0a5qxTBTQRgV+nfd8zDi4sOyyLO66Z+Y3+85995x7ztl777tvZ11cnOIUpzjFKU5xirVlQCaug7LJcs1m36AsfnbNolG4Llx8LosyaVs2MJtBDpe42+sMHDqfgiGZNAmY4PaQBWxTbBwi+eHzCZdk6gWEm8LOYfOIk/bhHgn0HpDBo27zGaK0yb3twi2t7zXpE2PXyY+aR7Z7Bs0CgmGMJGrKZuRcBo/OoEizaREW22XyHumEe6bRrOCVxlut7d6SoOj5numcEa61Zy99Fotti4LXXDubCRMSGTg2lXoBQUueXj6prBD9htau0pEfub9Y63fVO5UBdlOAl5PZICAYWpO/q61Z+Gx8MpP8U3ncZDGTKVbtkvi8tc0ng76+yWQKRXLvgnBdaBS9RmnzTSFlYjxP9EjyASm4TkqkSbg5MfXOmg9IYqnoCHWTE9GZ5S+BF8TutnArMJnnAxLJk+sGzV9H1EnfFWLziE0LEKQnS6cHYaeqy3KQ6+tCs24OwZb4FNtCzWeD9on4qgiaQ3pgHCMCY3hMmU1SrJG6BDLkfmVrv0A934TE2nD5TImnXCAkjjhNX63q8Wyx1GdoPImKD41zU/UEmrJR+kjfWs3mos2KEBbLWYGw2bip+my+U/VZBFjsM57Bqo9YjkYm8mQ74zZqY60J1fOsWrgY+k2P5Zhme9ImyyFiFg0CMTItNb1e0cPDTW94JvyWtfps5z530ThzFnqlXWz6iV6rtS/v9gJEv8YtgWQrV1sSebij+wlyqoyKwj86mm3K+CrRd4og7TqtrS6+u58Os6Ooi41SZ0D/nnoMx0aSLjG0CI36qDvLQa4PKXHFRZPUrYPrZ1IrMCeKcT15FtFHsFWNYyZr1BkykwxNN3TrwKkRbEmJgJRwcnqyAEnh+GtxnFH0tEhGqnoENVYdKC2ckLQZFGTMoCZ9Bo0CGr+ZWrfdKZmyYWpxNKhfjGzCml5vlQEWhOGWOZ0qgfZY8CqR98vxPHsafbS4ul6ARWEELJzGFYFF07iUPZWcxWF4LZ1C7/v1/eSNUNyVeIWuLYE35ZtfEsoVgSVT2bWsi893W8mSKWSoMYd2cRNcHkKVgLBLecuzlzfUFSEcUeN+hUSLneQGE5ITDMKlZf728c0rslKHr8TcosT+ThAJFjvKC6IgTwfymeNiR7I6iKESd6kau44mIcoiR/mTqRFYq8PT3n6iQ5ZrfgDvKvELl/ODecZsJ+smUS+wzo6mf9sirAugXMnh/QALZvF6fxqFbinAoq84LtCGamuP84E/IUoO6/341mzjjydwTuBDP7ysHdjS42AMa4+zfgL9lByEOrONP/Vlo4Cw0tqBvV0NxrD2OBtl9mo5NJhtvGEcwQXjQPh7qy99rBlY7jEwhrULUDCeIC2H0xY52OTDMYHNYzHkufCQ1R5VR8EY1i6AxF6qxC+sssjBNi+GbfXmqoBgKPShrzUCW1slj1cjWDP5bd7kaHHXFXrzlMWOtnvht9OTqwLCP4We5O7w4KVC9/Z/szO5Ox8BY3Q1aSWmQg+CJM5SLd6mHZ4WHoTulqLRDDV4UCVgCW39fXQYjNG2n6Xjafxr8LTyK3qJB8F7R1Mg3BToLG39fHIIjNG2nzljaDQLp/aOIXe3B0932ymrbBQV5aOg3N2yR2RBpezMRrA0HokjV41nFJU2OWYecmNaxQgQmoW8ytHmnbU3VcjObARz4zjsTv/KEazS4mgRQm121j48nPcOu0FnuGeHPgjGuGeMTvoXWoQVNn/hOD6M6dUv8qXQKNAe9+zWB8AYbft15FOjQWKorHZjkl29qe3eD8ZweRCkZB8TBYxRegA/h0x6Xzmn9peDWZRx0mEKcEiSETCTrx2mAFWljDxawg2BTvJfVRljHGoZnChh4Ym90EmyHW4fAHqd2kO5gAkOKn0dcjM8vYcB3xdz+UwxtEPdD8W4OvRj8KdiIn8sAmPIvdkPxFngbBFbzu2Gu6ndzWaXB0V+LaTveQPnBRQuGPjj99Ie+rdnT8lfhfj8+QW/CLXKtYtTnOIUpzjFKU6xtfwPyqY36Cv3XNYAAAAASUVORK5CYII='))
		icon = QtGui.QIcon(pixmap)
		self.setWindowIcon(icon)
		self.resize(390,190)

		self.lblMe = QLabel()
		self.lblStat = QLabel()
		self.lblTitle = QLabel()
		self.txtURL = QTextEdit()
		self.txtVideoID = QLineEdit()
		self.btnDownload = QPushButton("Download")
		self.btnGetLink = QPushButton("Get Link")
		self.combo = QComboBox()
		self.combo.addItem("480p")
		self.combo.addItem("240p")

		self.formGroupBoxA = QGroupBox("Video ID")
		layout_a = QFormLayout()
		layout_a.addRow(QLabel("ID"), self.txtVideoID)
		layout_a.addRow(QLabel("Quality"), self.combo)
		layout_a.addRow(QLabel(""), self.btnGetLink)
		self.formGroupBoxA.setLayout(layout_a)
		
		self.formGroupBoxB = QGroupBox("Video URL")
		layout_b = QFormLayout()
		layout_b.addRow(QLabel("Title"), self.lblTitle)
		layout_b.addRow(QLabel("URL"), self.txtURL)
		layout_b.addRow(QLabel(""), self.btnDownload)
		self.formGroupBoxB.setLayout(layout_b)

		self.formGroupBoxC = QGroupBox("")
		layout_status = QFormLayout()
		layout_status.addRow(QLabel("Status: "), self.lblStat)
		self.formGroupBoxC.setLayout(layout_status)
		self.formGroupBoxC.setFlat(True)

		layout = QVBoxLayout()
		layout.addWidget(self.formGroupBoxA)
		layout.addWidget(self.formGroupBoxB)
		layout.addWidget(self.formGroupBoxC)
		# layout.addWidget(self.lblMe)
		self.setLayout(layout)

		# self.lblMe.setText("<a href=https://github.com/thiwaK><font size=5 color=yellow><sub>thiwaK</sub></font></a>")
		# self.lblMe.setAlignment(QtCore.Qt.AlignRight)
		self.txtURL.setPlainText("")
		self.btnDownload.clicked.connect(self.btnDownload_Clicked)
		self.btnGetLink.clicked.connect(self.btnGetLink_Clicked)

		t1=Thread(target=self.init)
		t1.start()

	def Operation(self, URL):
		URL = URL.strip()
		regex = re.compile(
				r'^(?:http|ftp)s?://'
				r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
				r'localhost|'
				r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
				r'(?::\d+)?'
				r'(?:/?|[/?]\S+)$', re.IGNORECASE)

		if not (re.match(regex, URL) is not None):
			print("[-] Invalid URL")
			return
		today = date.today()
		now = datetime.now()
		dt_string = now.strftime("%Y_%m_%d__%H.%M.%S")

		print("\n\n - Save to : ", OUT,"\\",dt_string,".mp4")
		print("-------------------------------------------------\n\n")
		os.system(f"lib\\ffmpeg.exe -i \"{URL}\" -bsf:a aac_adtstoasc -v warning -stats -f mp4 -c copy \"{OUT}\\{dt_string}.mp4\"")
		'''
		# First 10 Minutes                      -ss 0 -t 00:10:00 
		# Second 10 Minutes                     -ss 00:10:00 -t 00:20:00
		# Rest after the first 20 Minutes       -ss 00:20:00
		'''

	def btnDownload_Clicked(self):

		self.btnDownload.setText("Downloading ...")
		self.btnDownload.setEnabled(False)
		self.txtVideoID.setText("")

		URL = self.txtURL.toPlainText()
		t1=Thread(target=self.Operation, args=(URL,))
		t1.start()

		self.btnDownload.setText("Download")
		self.btnDownload.setEnabled(True)

	def btnGetLink_Clicked(self):
		self.txtURL.setPlainText("")
		self.lblTitle.setText("")
		if(len(self.txtVideoID.text()) == 9):

			self.sendVideoID(self.txtVideoID.text())
			self.txtVideoID.setText("")

		else:
			print("[-] Invalid Video ID : ", self.txtVideoID.text())

	def init(self):
		global OUT
		print("[+] Initalizing ...")
		chr_list = ['0','1','2','3','4','5','6','7','8','9',
		'a','b','c','d','e','f']

		if os.name == 'nt':
			OUT = os.environ['USERPROFILE'] + "\\Downloads\\" + OUT
		else:
			exit()

		if not (os.path.exists(OUT)):
			os.makedirs(OUT)

		# try:
		# 	with open("lib\\dev.inf",'r') as f:
		# 		DEVICE =  f.read()
		# except Exception as e:
		# 	for _ in range(0, 16):
		# 		DEVICE += chr_list[random.randint(0,15)]
		# 	with open("lib\\dev.inf",'w') as f:
		# 		f.write(DEVICE)
		# print("    - Device OK")

		

		try:
			with open("lib\\user.inf",'r') as f:
				raw_response =  f.read()
		except Exception as e:
			session.headers.update({"Authorization" : "Bearer"})
			data = r""""""
			data += r"""{"operationName":"LoginAdmin","variables":{"input":{"mobile":""" + '\"' + MOBILE_NO + '\"' + r""","password":""" + '\"' + PASSWORD + '\"' + r"""}},"query":"mutation LoginAdmin($input: UserLogIn) {loginStudent(input: $input) {\n      accessToken\n      userAccount {\n        _id\n        fname\n        lname\n        email\n        mobile\n        role\n        status\n        created_at\n        updated_at\n      }\n    }\n  }"}"""
			url = API + "/api/gql"

			r = session.request("POST", url, data=data)
			raw_response = r.text
			
			with open("lib\\user.inf",'w') as f:
				f.write(raw_response)

		self.init_parser(raw_response)

		session.headers.update({"Authorization" : TOKEN})
		data = r"""{"variables":{},"query":"{\n  myCourses {\n    myCourses {\n      _id\n      teacher_profile_id\n      teacher_account_id\n      title\n      description\n      monthly_fee\n      teacher_full_name\n      subject\n      subject_id\n      exm_year\n      status\n      avatar_url\n      cover_url\n      created_at\n      updated_at\n      deleted_at\n      __typename\n    }\n    __typename\n  }\n}\n"}"""
		url = API + "/api/gql"

		r = session.request("POST", url, data=data)
		raw_response = r.text

		jsonData = json.loads(raw_response)
		try:
			if(jsonData["errors"][0]["message"]=="TokenExpiredError: jwt expired"):
				print("   - ReLogin")
				session.headers.update({"Authorization" : "Bearer"})
				data = r"""{"operationName":"LoginAdmin","variables":{"input":{"mobile":""" + '\"' + MOBILE_NO + '\"' + r""","password":""" + '\"' + PASSWORD + '\"' + r"""}},"query":"mutation LoginAdmin($input: UserLogIn) {loginStudent(input: $input) {\n      accessToken\n      userAccount {\n        _id\n        fname\n        lname\n        email\n        mobile\n        role\n        status\n        created_at\n        updated_at\n      }\n    }\n  }"}"""
				url = API + "/api/gql"

				r = session.request("POST", url, data=data)
				raw_response = r.text
				
				with open("lib\\user.inf",'w') as f:
					f.write(raw_response)
		except Exception as e:
			pass

		print("    - User OK")

		self.sendDeviceID()

	def init_parser(self,raw_data):
		global TOKEN, USER
		jsonData = json.loads(raw_data)
		TOKEN = jsonData["data"]["loginStudent"]["accessToken"]
		USER = jsonData["data"]["loginStudent"]["userAccount"]

		# print(USER)
		# print(TOKEN)
		
	def sendDeviceID(self):
		print("    - Sending Device ID")
		session2 = requests.session()
		session2.headers.update({"App" : "aplu"})
		session2.headers.update({"Authorization" : TOKEN})
		session2.headers.update({"Content-Type" : "application/x-www-form-urlencoded"})
		session2.headers.update({"Accept-Encoding" : "gzip"})
		session2.headers.update({"User-Agent" : User_Agent})
		
		data = rf"""device={DEVICE}"""
		url = "https://viddownlk.herokuapp.com" + "/accessMgr.php"

		r = session2.request("POST", url, data=data)
		raw_response = r.text

	def sendVideoID(self,VIDEO_CODE):
		
		session.headers.update({"Authorization" : TOKEN})
		data = r"""{"operationName":"GetLessonContent","variables":{"devModel":"android-v2.2ede87e666b74d2d80566fc1988c11ff","link":"""+ '"' + VIDEO_CODE + '"' + r"""},"query":"query GetLessonContent($link: String, $devModel: String) {\n    getLessonContent(link_param: $link, dev_model: $devModel) {\n      lesson {\n        _id\n        title\n        description\n        video_code\n        subject\n      }\n      is_subscribed\n      lesson_viewer_key\n      vid_url\n      m_vid_url\n      key\n      hash\n    }\n  }"}"""
		url = API + "/api/gql"

		r = session.request("POST", url, data=data)
		raw_response = r.text

		self.sendVideoID_parser(raw_response)

	def sendVideoID_parser(self,raw_data):

		global V_KEY, V_HASH
		
		jsonData = json.loads(raw_data)
		try:
			print("[-]", jsonData['errors'][0]['message'])
			print("[!] Refresh your video ID")
		except Exception as e:
			print("[+] Parse Video data")
			V_ID = jsonData["data"]["getLessonContent"]["lesson"]["_id"]
			V_URL = jsonData["data"]["getLessonContent"]["vid_url"]
			V_URL_M = jsonData["data"]["getLessonContent"]["m_vid_url"]
			V_KEY = jsonData["data"]["getLessonContent"]["key"]
			V_HASH = jsonData["data"]["getLessonContent"]["hash"]
			self.lblTitle.setText(jsonData['data']['getLessonContent']['lesson']['title'])

			self.getPlayList()
	
	def getPlayList(self):
	
		global PLAY_LIST, PLAY_LIST_KEY, PLAY_LIST_HASH
		session4 = requests.session()
		session4.headers.update({"Content-Type" : "application/x-www-form-urlencoded"})
		session4.headers.update({"Accept-Encoding" : "gzip"})
		session4.headers.update({"User-Agent" : User_Agent})
		session4.headers.update({"Device" : DEVICE})

		data = rf"""data={V_KEY}&iv={V_HASH}"""
		url = "https://aplusewings.herokuapp.com" + "/aplus/keydecrypt.js?apiv2"
		r = session4.request("POST", url, data=data)
		raw_response = r.text

		jsonData = json.loads(raw_response)
		if(jsonData['ok']):
			PLAY_LIST = jsonData['output']["playlist_url"]
			PLAY_LIST_KEY = jsonData['output']["raw_key"]
			PLAY_LIST_HASH = jsonData['output']["playlist_decryption_hash"]
	
		self.decodePlayList()

	def decodePlayList(self):

		global PLAY_LIST
		PLAY_LIST = PLAY_LIST[:-8] + "v1/" + PLAY_LIST[-8:]

		session3 = requests.session()
		session3.headers.update({"Content-Type" : "application/x-www-form-urlencoded"})
		session3.headers.update({"Device" : DEVICE})
		session3.headers.update({"Accept-Encoding" : "gzip"})
		session3.headers.update({"User-Agent" : User_Agent})

		r = session.request("POST", PLAY_LIST)
		raw_response = r.text

		self.getM3u8(raw_response)

	def getM3u8(self,vid_data):

		session3 = requests.session()
		session3.headers.update({"Content-Type" : "application/x-www-form-urlencoded"})
		session3.headers.update({"Device" : DEVICE})
		session3.headers.update({"Accept-Encoding" : "gzip"})
		session3.headers.update({"User-Agent" : User_Agent})

		data = r"url=" + PLAY_LIST + "&keyurl=" + PLAY_LIST_KEY + "&iv=" + PLAY_LIST_HASH + "&data=" + vid_data

		r = session3.request("POST", "https://aplusewings.herokuapp.com/aplus/playlistdecrypt.js?apiv2", data=data)
		raw_response = r.text

		jsonData = json.loads(raw_response)
		if(jsonData['ok']):
			self.txtURL.setPlainText(jsonData['output'])

if __name__ == '__main__':

	try:
		with open("lib\\cred.inf",'r') as f:
			data =  f.read()
			jsonData = json.loads(data)
			MOBILE_NO = jsonData['user']
			PASSWORD = jsonData['pass']
	except Exception as e:
		login = QApplication(sys.argv)
		win = Login()
		win.show()
		sys.exit(login.exec_())

	app = QApplication(sys.argv)
	win = aPlus()
	win.show()
	sys.exit(app.exec_())