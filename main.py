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
	from datetime import timedelta
	from requests import session
	import os
	import re
	import io
	import sys
	import time
	import signal
	import base64
	import subprocess
	import json, base64
except Exception:
	import os
	print("Trying to Install required modules ...\n")
	os.system('python -m pip install PyQt5 requests')
	exit()


output_folder = "aPlus_Downloads" 	# Output folder name in your Downloads(C:\Users\YOUR_USER_NAME\Downloads) folder
DEBUG = 0 							# Enable/Disable Debug output



class Worker(QObject):
	finished = pyqtSignal()
	progress = pyqtSignal(int)

	def __init__(self):
		super(QObject, self).__init__()
		self.URL = ""

	def kill(self):
		print("[+] Terminate -> ", end='')
		subprocess.Popen("TASKKILL /F /IM ffmpeg.exe /T")
		
	def run(self):
		
		today = date.today()
		now = datetime.now()
		dt_string = now.strftime("%Y_%m_%d__%H.%M.%S")

		print("[+] output :", output_folder + "\\" + dt_string + ".mp4")
		cmd = f"lib\\ffmpeg.exe -i \"{self.URL}\" -bsf:a aac_adtstoasc -v info -f mp4 -c copy \"{output_folder}\\{dt_string}.mp4\""
		# cmd = f"ping localhost -n 5"
		'''
		# First 10 Minutes                      -ss 0 -t 00:10:00 
		# Second 10 Minutes                     -ss 00:10:00 -t 00:20:00
		# Rest after the first 20 Minutes       -ss 00:20:00
		'''

		process = subprocess.Popen(
		cmd,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		shell=True,
		encoding='utf-8',
		bufsize = 1,
		errors='replace')

		duration_regex = r"(Duration: )(\d\d:\d\d:\d\d.\d\d)"
		current_progress_regex = r"(time=)(\d\d:\d\d:\d\d.\d\d)"
		self.progress.emit(0)
		while True:

			realtime_output = str(process.stdout.readline()).strip()
			if realtime_output == '' and process.poll() is not None:
				break

			if realtime_output:
				if re.match(duration_regex, realtime_output):
					self.video_duration = re.findall(duration_regex, realtime_output)[0][1]
					print("[+] Duration:", self.video_duration)
				
				elif("time=" in realtime_output):
					current_progress = re.findall(current_progress_regex, realtime_output)[0][1]
					
					x = time.strptime(current_progress.split('.')[0],'%H:%M:%S')
					y = time.strptime(self.video_duration.split('.')[0],'%H:%M:%S')
					progress_in_sec = timedelta(hours=x.tm_hour,minutes=x.tm_min,seconds=x.tm_sec).total_seconds()
					duration_in_sec = timedelta(hours=y.tm_hour,minutes=y.tm_min,seconds=y.tm_sec).total_seconds()

					self.progress.emit(int((progress_in_sec/duration_in_sec)*100))
					# print(int((progress_in_sec/duration_in_sec)*100))

				else:
					pass


		print("[+] End download")
		process.kill()
		self.finished.emit()

class Client():
	'''API Client. Handle all API calls'''

	def __init__(self, main):
		
		global output_folder, DEBUG
		if(DEBUG):
			import requests
			import logging
			import http.client as http_client
			logging.basicConfig()
			logging.getLogger().setLevel(logging.DEBUG)
			requests_log = logging.getLogger("requests.packages.urllib3")
			requests_log.setLevel(logging.DEBUG)
			requests_log.propagate = True
		
		print("[+] Initalizing ...")
		self.main = main
		
		if os.name == 'nt':
			output_folder = os.environ['USERPROFILE'] + "\\Downloads\\" + output_folder
		else:
			print("[-] Currently support for Windows OS only")
			exit()
		if not (os.path.exists(output_folder)):
			os.makedirs(output_folder)

		self.CRED_FILE = "lib\\cred.bin"
		self._getCredential()
		self.readDefaultConfig()

		self.CONFIG = {}
		self.CONFIG['Aplus'] = {
			'URL' : {
				'dev_reg':'https://livetechdl.herokuapp.com/device_check.php',
				'dec_key':'https://aplusewings.herokuapp.com/aplus/keydecrypt.js?apiv2',
				'dec_playlist':'https://aplusewings.herokuapp.com/aplus/playlistdecrypt.js?apiv2',
				'api':'https://api.apluseducation.lk/api/gql'
			}
		}
		self.session = session()
		self.default_headers = {"User-Agent" : "Dart/2.10 (dart:io)", 
		"Content-Type" : "application/json", "Accept-Encoding" : "gzip", "Accept" : "*/*"}

		if(self.CRED[self.CRED['app']]['status'] == 0):
			# need to login
			print("[+] Welcome !")
			login = QApplication(sys.argv)
			win = Login(self)
			win.show()
			sys.exit(login.exec_())
			exit()

		elif(self.CRED[self.CRED['app']]['status'] == 1):
			# need to register the device
			print("[+] Registering device")
			self.registerDevice()
			return

		elif(self.CRED[self.CRED['app']]['status'] == 2):
			# ready to go !
			return

		else:
			print("[!] Something wrong. Re-clone the repo")
			exit()

	def merge(self, x, y):
		z = x.copy()
		z.update(y)
		return z

	def readDefaultConfig(self):
		try:
			with open("lib\\defualt.conf") as fhandle:
				self.default_config = json.loads(fhandle.read())
		except Exception as e:
			self.default_config = {'theme': 0}

	def writeDefaultConfig(self):
		try:
			with open("lib\\defualt.conf", 'w') as fhandle:
				fhandle.write(json.dumps(self.default_config))
		except Exception as e:
			print("[-] ERROR ", e)

	def _getCredential(self):
		'''load authentication details'''
		try:
			with open(self.CRED_FILE,'rb') as f:
				data = base64.a85decode(f.read()).decode('utf-8')
				if(data == ''):
					data = """{"app":"Aplus","Aplus":{"cred":{"user":"","pass":""},"dev_id":"","token":"","status":0,"user":""},"Ewings":{"cred":{"user":"","pass":""},"dev_id":"","token":"","status":0,"user":""}}"""
					self.CRED = json.loads(data)
				else:
					self.CRED = json.loads(data)
					print("[+] Credentials loaded")
		except FileNotFoundError as e:
			data = """{"app":"Aplus","Aplus":{"cred":{"user":"","pass":""},"dev_id":"","token":"","status":0,"user":""},"Ewings":{"cred":{"user":"","pass":""},"dev_id":"","token":"","status":0,"user":""}}"""
			self.CRED = json.loads(data)

	def _updateCredential(self):
		'''write authentication details'''
		with open(self.CRED_FILE, 'wb') as f:
			data = json.dumps(self.CRED, ensure_ascii=False, indent=4)
			encoded_data = base64.a85encode(data.encode())
			f.write(encoded_data)

	def registerDevice(self):
		'''Register current device in remote server'''
		
		print("[+] Registering device...")
		headers = self.merge(self.default_headers, {"App" : self.CRED['app'],"Content-Type" : 'application/x-www-form-urlencoded',"Authorization" : self.CRED[self.CRED['app']]['token'],"Device" : self.CRED[self.CRED['app']]['dev_id']})
		data = "student_id=%s" % self.CRED[self.CRED['app']]['user']['_id']
		response = self.session.request("POST", self.CONFIG[self.CRED['app']]['URL']['dev_reg'], data=data, headers=headers)
		raw_response = response.text
		js = json.loads(raw_response)
		if(js['ok']):
			self.CRED[self.CRED['app']]['status'] = 2
		else:
			print('[-] Failed')
			self.CRED[self.CRED['app']]['status'] = 1
		self._updateCredential()
		print("[+] Done")
		exit()

	def logout(self):
		print("[+] logging out")
		os.remove(output_folder)
		qApp.quit()
		exit()

	def login(self, mobile_number, password, app_name):
		'''login into online account(Aplus)'''
		print("[+] Login...")
		chr_list = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']

		headers = self.merge(self.default_headers, {"Authorization" : "Bearer", "Content-Type" : "application/json"})
		data = "{\"operationName\":null,\"variables\":{\"input\":{\"mobile\":\"%s\",\"password\":\"%s\"}},\"query\":\"mutation LoginAdmin($input: UserLogIn) {\\n  __typename\\n  loginStudent(input: $input) {\\n    __typename\\n    accessToken\\n    userAccount {\\n      __typename\\n      _id\\n      fname\\n      lname\\n      email\\n      mobile\\n      role\\n      status\\n      created_at\\n      updated_at\\n    }\\n  }\\n}\"}"
		data = data % (mobile_number, password)
		try:
			response = self.session.request("POST", self.CONFIG[app_name]['URL']['api'], data=data, headers=headers)
			raw_response = response.text

			jsonData = json.loads(raw_response)
			TOKEN = jsonData["data"]["loginStudent"]["accessToken"]
			USER = jsonData["data"]["loginStudent"]["userAccount"]
			
			DEVICE = ""
			for _ in range(0, 16):
				DEVICE += chr_list[random.randint(0,15)]

			self.CRED['app'] = app_name
			self.CRED[app_name]['cred']['user'] = mobile_number
			self.CRED[app_name]['cred']['pass'] = password
			self.CRED[app_name]['user'] = USER
			self.CRED[app_name]['token'] = TOKEN
			
			if(self.CRED[app_name]['status']==0):
				self.CRED[app_name]['dev_id'] = DEVICE
				self.CRED[app_name]['status'] = 1

			self._updateCredential()


			return 1

		except Exception as e:
			print("[-] Failed", e)
			return 0

	def reAuth(self):
		print("[+] Re-Authorize")
		self.CRED[self.CRED['app']]['status'] = 0
		self._updateCredential()
		self.updateAuth()
	
	def updateAuth(self):
		print("[+] Update token. Retry")
		self.login(self.CRED[self.CRED['app']]['cred']['user'], self.CRED[self.CRED['app']]['cred']['pass'], self.CRED['app'])


	def sendVideoID(self, VIDEO_ID):
		
		print("[+] Send video id")
		headers = self.merge(self.default_headers, {"Authorization" : self.CRED[self.CRED['app']]['token'], "Content-Type" : "application/json"})
		data = "{\"operationName\":null,\"variables\":{\"link\":\"%s\",\"devModel\":\"android-v2.278890df33ce40d6937df5138e3f7d58\"},\"query\":\"query GetLessonContent($link: String, $devModel: String) {\\n  __typename\\n  getLessonContent(link_param: $link, dev_model: $devModel) {\\n    __typename\\n    lesson {\\n      __typename\\n      _id\\n      title\\n      description\\n      video_code\\n      subject\\n    }\\n    is_subscribed\\n    lesson_viewer_key\\n    vid_url\\n    m_vid_url\\n    key\\n    hash\\n  }\\n}\"}"
		data = data % VIDEO_ID

		r = self.session.request("POST", self.CONFIG[self.CRED['app']]['URL']['api'], data=data, headers=headers)
		raw_response = r.text
		jsonData = json.loads(raw_response)
		try:
			if(jsonData['errors'][0]['message'] == "TokenExpiredError: jwt expired"):
				self.updateAuth()
			elif (jsonData['errors'][0]['message'] == "Unexpected error value: \"Watch time exceeded\""):
				print("[-] Watch time exceeded. Try again later")
				return 0
			else:
				print("[-]", jsonData['errors'][0]['message'])	
			return 0

		except Exception as e:
			print("[+] Parsing Video data")
			self.V_ID = jsonData["data"]["getLessonContent"]["lesson"]["_id"]
			V_URL = jsonData["data"]["getLessonContent"]["vid_url"]
			V_URL_M = jsonData["data"]["getLessonContent"]["m_vid_url"]
			self.V_KEY = jsonData["data"]["getLessonContent"]["key"]
			self.V_HASH = jsonData["data"]["getLessonContent"]["hash"]
			self.main.lblTitle.setText(jsonData['data']['getLessonContent']['lesson']['title'])
			return 1

	def decryptKey(self):
	
		print("[+] Decrypt key")
		headers = self.merge(self.default_headers, {"App" : self.CRED['app'],"Content-Type" : 'application/x-www-form-urlencoded',"Authorization" : self.CRED[self.CRED['app']]['token'],"Device" : self.CRED[self.CRED['app']]['dev_id']})
		data = rf"""data={self.V_KEY}&iv={self.V_HASH}&lesson_id={self.V_ID}&student_id={self.CRED[self.CRED['app']]['user']['_id']}&custom_timestamp={round(time.time() * 1000)}"""
		r = self.session.request("POST", self.CONFIG[self.CRED['app']]['URL']['dec_key'], data=data, headers=headers)
		raw_response = r.text

		jsonData = json.loads(raw_response)
		if(jsonData['ok']):
			self.PLAY_LIST_URL = jsonData['output']["playlist_url"]
			self.PLAY_LIST_KEY = jsonData['output']["raw_key"]
			self.PLAY_LIST_HASH = jsonData['output']["playlist_decryption_hash"]
			return 1
		elif(jsonData['output'] == 'Invalid device id'):
			print("[!] Warning. Device must register")
			self.CONFIG[self.CRED['app']]['status'] = 1
			self._updateCredential()
			self.registerDevice()
			exit()
		else:
			print("[-] Failed", jsonData)
			return 0

	def decodePlayList(self):

		print("[+] Decode playlist")
		if(str(self.main.combo.currentText()) == "480p"):
			# self.PLAY_LIST_URL = self.PLAY_LIST_URL[:-8] + "v1/" + self.PLAY_LIST_URL[-8:]
			self.PLAY_LIST_URL = self.PLAY_LIST_URL.replace("/playback", "/v1/playback")
		else:
			# self.PLAY_LIST_URL = self.PLAY_LIST_URL[:-8] + "01/" + self.PLAY_LIST_URL[-8:]
			self.PLAY_LIST_URL = self.PLAY_LIST_URL.replace("/playback", "/v0/playback")

		headers = self.merge(self.default_headers, {"Content-Type" : "application/json"})

		if(DEBUG):
			print(headers)
			print(self.PLAY_LIST_URL)

		r = self.session.request("POST", self.PLAY_LIST_URL, headers=headers)
		if(r.status_code == 200):
			raw_response = r.text
			self.ENC_M3U8 = raw_response
			return 1
		else:
			print("[-] Failed -", r.text)
			return 0

	def getM3u8(self):

		print("[+] Getting link")
		headers = self.merge(self.default_headers, {"App" : self.CRED['app'],"Content-Type" : 'application/x-www-form-urlencoded',"Authorization" : self.CRED[self.CRED['app']]['token'],"Device" : self.CRED[self.CRED['app']]['dev_id']})
		data = r"url=" + self.PLAY_LIST_URL + "&keyurl=" + self.PLAY_LIST_KEY + "&iv=" + self.PLAY_LIST_HASH + "&data=" + self.ENC_M3U8

		r = self.session.request("POST", self.CONFIG[self.CRED['app']]['URL']['dec_playlist'], data=data, headers=headers)
		raw_response = r.text

		jsonData = json.loads(raw_response)
		if(jsonData['ok']):
			main.txtURL.setPlainText(jsonData['output'])
			return 1
		else:
			print("[-] Failed", raw_response)
			return 0

class Login(QDialog):
	'''Login UI'''

	def __init__(self, client, parent=None):
		super(Login, self).__init__(parent)
		self.client = client
		self.setWindowTitle("aPlus Login | thiwaK")
		pixmap = QtGui.QPixmap()
		pixmap.loadFromData(QtCore.QByteArray.fromBase64(b'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'))
		icon = QtGui.QIcon(pixmap)
		self.setWindowIcon(icon)
		self.resize(390,190)
		
		self.txtMobile = QLineEdit(self)
		self.txtPass = QLineEdit(self)
		self.btnLogin = QPushButton('Login', self)

		self.aplus = QRadioButton("A Plus")
		self.ewings = QRadioButton("E Wings")
		horizontal_box = QHBoxLayout()
		horizontal_box.addWidget(self.aplus)
		horizontal_box.addWidget(self.ewings)
		
		layout = QFormLayout(self)
		layout.addRow(QLabel("Mobile Number"), self.txtMobile)
		layout.addRow(QLabel("Password"), self.txtPass)
		layout.addRow(QLabel("Platform"), horizontal_box)
		layout.addRow(QLabel(""), self.btnLogin)
		self.setLayout(layout)

		self.btnLogin.clicked.connect(self.login)

	def login(self):
		PASSWORD, MOBILE_NO, APP = "","",""
		
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


		if self.aplus.isChecked():
			APP = 'Aplus'
		if self.ewings.isChecked():
			APP = 'Ewings'
		
		if(self.client.login(mobile_number=MOBILE_NO, password=PASSWORD, app_name=APP)):
			if(self.client.registerDevice()):
				msg = QMessageBox()
				msg.setIcon(QMessageBox.Information)
				msg.setWindowTitle("Login")
				msg.setText("Success !")
				x = msg.exec_()
				self.accept()

		else:
			msg = QMessageBox()
			msg.setIcon(QMessageBox.Critical)
			msg.setWindowTitle("Login")
			msg.setText("Error Login. Try Again")
			x = msg.exec_()
			return

class Main(QWidget):
	'''Main UI'''

	def __init__(self,parent=None):
		super().__init__(parent)

		self.client = Client(self)
		self.thread = QThread()
		self.worker = Worker()
		self.worker.moveToThread(self.thread)
		self.thread.started.connect(self.worker.run)
		self.worker.finished.connect(self.thread.quit)
		# self.worker.finished.connect(self.worker.deleteLater)
		# self.thread.finished.connect(self.thread.deleteLater)
		self.thread.finished.connect(self._endDownload)
		self.worker.progress.connect(self.statusUpdate)
		self.setWindowTitle("aPlus Downloader | thiwaK")
		# self.setWindowIcon(QtGui.QIcon('icon.png'))
		# self.icon = QtGui.QIcon()
		# self.icon.addPixmap(QtGui.QPixmap("icon.png"), QtGui.QIcon.Selected, QtGui.QIcon.On)
		pixmap = QtGui.QPixmap()
		pixmap.loadFromData(QtCore.QByteArray.fromBase64(b'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'))
		icon = QtGui.QIcon(pixmap)
		self.setWindowIcon(icon)
		self.resize(390,190)

		self.lblMe = QLabel()
		self.lblStat = QLabel()
		self.lblTitle = QLabel()
		self.txtURL = QTextEdit()
		self.txtURL.setPlaceholderText("paste your url here") 
		self.txtVideoID = QLineEdit()
		self.txtVideoID.setPlaceholderText("0000-0000") 
		self.btnDownload = QPushButton("Download")
		self.btnGetLink = QPushButton("Get Link")
		self.combo = QComboBox()
		self.combo.addItem("480p")
		self.combo.addItem("240p")
		self.pbar = QProgressBar()

		self.formGroupBoxA = QGroupBox("Video")
		layout_a = QFormLayout()
		layout_a.addRow(QLabel("ID"), self.txtVideoID)
		layout_a.addRow(QLabel("Quality"), self.combo)
		layout_a.addRow(QLabel(""), self.btnGetLink)
		self.formGroupBoxA.setLayout(layout_a)
		
		self.formGroupBoxB = QGroupBox("Download")
		layout_b = QFormLayout()
		layout_b.addRow(QLabel("Title"), self.lblTitle)
		layout_b.addRow(QLabel(""))
		layout_b.addRow(QLabel("URL"), self.txtURL)
		layout_b.addRow(QLabel(""), self.btnDownload)
		self.formGroupBoxB.setLayout(layout_b)

		self.formGroupBoxC = QGroupBox("")
		self.layout_status = QFormLayout()
		self.layout_status.addRow(QLabel("Status: "), self.lblStat)
		self.layout_status.addRow(QLabel(""), self.pbar)
		self.formGroupBoxC.setLayout(self.layout_status)
		self.formGroupBoxC.setFlat(True)

		self.formGroupBoxD = QGroupBox("User")
		layout_user = QFormLayout()
		layout_user.addRow(QLabel("Name: "), QLabel("%s %s"% (self.client.CRED[self.client.CRED['app']]['user']['fname'].title(), self.client.CRED[self.client.CRED['app']]['user']['lname'].title())))
		layout_user.addRow(QLabel("ID: "), QLabel("%s" % self.client.CRED[self.client.CRED['app']]['user']['_id']))
		# layout_user.addRow(QLabel("Name: "), QLabel("Your Name"))
		# layout_user.addRow(QLabel("ID: "), QLabel("Your User ID"))
		self.formGroupBoxD.setLayout(layout_user)

		menubar = QMenuBar()
		actionFile = menubar.addMenu("File")
		exitAct = actionFile.addAction("Quit")
		exitAct.setShortcut('Ctrl+Q')
		exitAct.setStatusTip('Exit application')
		exitAct.triggered.connect(qApp.quit)
		
		nextTheme = actionFile.addAction("Switch Theme")
		nextTheme.setShortcut('')
		nextTheme.triggered.connect(self.changeTheme)

		actionUser = menubar.addMenu("User")
		updateToken = actionUser.addAction("Reauthenticate")
		updateToken.setShortcut('')
		updateToken.triggered.connect(self.client.updateAuth)

		reAuth = actionUser.addAction("Forced Reauthenticate")
		reAuth.setShortcut('')
		reAuth.triggered.connect(self.client.reAuth)

		switchApp = ""
		if(self.client.CRED['app'] == "Aplus"):
			switchApp = actionUser.addAction("Switch to Ewings")
			switchApp.setShortcut('')
			# switchApp.triggered.connect(self.client.reAuth)
		if(self.client.CRED['app'] == "Ewings"):
			switchApp = actionUser.addAction("Switch to Aplus")
			switchApp.setShortcut('')
			# switchApp.triggered.connect(self.client.reAuth)

		logout = actionUser.addAction("Logout")
		logout.setShortcut('')
		logout.triggered.connect(self.client.logout)

		layout = QVBoxLayout()
		layout.addWidget(menubar)
		layout.addWidget(QLabel(""))
		layout.addWidget(self.formGroupBoxD)
		layout.addWidget(self.formGroupBoxA)
		layout.addWidget(self.formGroupBoxB)
		layout.addWidget(self.formGroupBoxC)
		# layout.addWidget(self.lblMe)
		self.setLayout(layout)
		self.updateTheme()

		
		# self.lblMe.setText("<a href=https://github.com/thiwaK><font size=5 color=yellow><sub>thiwaK</sub></font></a>")
		# self.lblMe.setAlignment(QtCore.Qt.AlignRight)
		self.txtURL.setPlainText("")
		self.pbar.hide()
		self.btnDownload.clicked.connect(self.btnDownload_Clicked)
		self.btnGetLink.clicked.connect(self.btnGetLink_Clicked)
		self.statusUpdate()


	def changeTheme(self):
		if(self.client.default_config['theme'] == 0):
			self.client.default_config['theme'] = 1
		else:
			self.client.default_config['theme'] = 0
		self.client.writeDefaultConfig()

	def updateTheme(self):
		if(self.client.default_config['theme'] == 0):
			self.setStyleSheet(open('lib/light.qtheme').read())
		if(self.client.default_config['theme'] == 1):
			self.setStyleSheet(open('lib/dark.qtheme').read())
		else:
			self.setStyleSheet = ""

	def runLongTask(self):
		self.thread = QThread()
		self.worker = Worker()
		self.worker.moveToThread(self.thread)
		self.thread.started.connect(self.worker.run)
		self.worker.finished.connect(self.thread.quit)
		self.worker.finished.connect(self.worker.deleteLater)
		self.thread.finished.connect(self.thread.deleteLater)
		self.worker.progress.connect(self.statusUpdate)
		self.thread.start()
		
		self.thread.finished.connect(
			lambda: self.lblTitle.setText("Long-Running Step: 0")
		)

	def btnDownload_Clicked(self):

		self.btnDownload.setEnabled(False)
		self.statusUpdate("Downloading...")
		self.btnDownload.setText("Cancel Download")
		self.btnDownload.setStyleSheet("background-color: #FF2B7D; color:#FFDAE8 ")
		self.btnDownload.clicked.connect(self.cancelDownload)
		self.btnDownload.setEnabled(True)
		self.btnGetLink.setEnabled(False)
		self.txtVideoID.setText("") 
		

		URL = self.txtURL.toPlainText().strip()
		regex = re.compile(
				r'^(?:http|ftp)s?://'
				r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
				r'localhost|'
				r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
				r'(?::\d+)?'
				r'(?:/?|[/?]\S+)$', re.IGNORECASE)

		if not (re.match(regex, URL) is not None):
			print("[-] Invalid URL")
			self.statusUpdate("Invalid URL")
			return

		self._startDownload(URL)
		
	def _startDownload(self, URL):
		
		self.worker.URL = URL
		self.thread.start()

	def _endDownload(self):
		self.btnDownload.clicked.connect(self.btnDownload_Clicked)
		self.btnDownload.setStyleSheet("")
		self.btnDownload.setText("Download")
		self.btnDownload.setEnabled(True)
		self.btnGetLink.setEnabled(True)
		self.statusUpdate()
	
	def cancelDownload(self):

		self.worker.kill()

	def btnGetLink_Clicked(self):
		self.txtURL.setPlainText("")
		self.lblTitle.setText("")

		self.statusUpdate("Initiating Download...")
		QApplication.processEvents()
		if(len(self.txtVideoID.text()) == 9):
			
			self.statusUpdate("Send video id...")
			QApplication.processEvents()
			if(self.client.sendVideoID(self.txtVideoID.text())):
				
				self.statusUpdate("Decrypt key...")
				QApplication.processEvents()
				if(self.client.decryptKey()):

					self.statusUpdate("Decode playlist...")
					QApplication.processEvents()
					if(self.client.decodePlayList()):

						self.statusUpdate("Get link...")
						QApplication.processEvents()
						self.client.getM3u8()
						self.statusUpdate()
					else:
						self.statusUpdate("Failed")
				else:
					self.statusUpdate("Failed")
			else:
				self.statusUpdate("Check your video ID")
		else:
			self.statusUpdate("Invalid Video ID")
			print("[-] Invalid Video ID")

		self.txtVideoID.setText("")

	def statusUpdate(self, text='idle'):
		
		try:
			text = int(text)
			self.pbar.setValue(text)
			self.pbar.show()
		except:
			self.pbar.hide()
			self.lblStat.setText(str(text))

if __name__ == '__main__':

	app = QApplication(sys.argv)
	main = Main()
	main.show()
	sys.exit(app.exec_())