# aPlus Downloader 1.0.35
Download and save m3u8 streams

---

[![Build Status](https://travis-ci.org/joemccann/dillinger.svg?branch=master)](https://travis-ci.org/joemccann/dillinger)

aPlus downloader is originally developed for downloading videos hosted in aplus education platform. By using a 9-digit code (xxxx-xxxx), the software allows generating an m3u8 link, which can be used to download relevant video. By using that link or any other m3u8 link, the video stream can be saved to local storage.

![](https://raw.githubusercontent.com/thiwaK/m3u8_downloader/master/screenshot/2.png)

---

Note: Currently this tool is support only for aPlus education platform. But it can developed to support E-Wings. If you are an Ewings user or know to get it done, contact me or contribute.

### Requirements 

aPlus Downloader is a python-based GUI. The following requirements must be satisfied in order to use this.

* python 3.x must be installed and must add to PATH (environment variable).
* Windows operating system (XP/Vista/7/8/8.1/10/11)

---

### Installation

* Clone the repo or download the zip and extract anywhere. Desktop is the best place if you are not a tech-savvy.
* Run aPlus_Video_Downloader

Note: There are additional Python modules needed to successfully run and they will be installed automatically. Make sure you have connected to the internet when you run this programe !

---

### How to use

Currently, this tool cannot be used without login into apluseducation platform.

* Login with your aPlus username and password
* In the main UI, you have two options
   - You can enter your Video ID and get the link
   - You can directly enter the link
* Either way, after getting the m3u8 link, simply hit Download.

Note: Downloaded videos will be saved to aPlus_Downloads folder in your Downloads directory (`C:\Users\YOUR_USER_NAME\Downloads\aPlus_Downloads`). But if you want, you can change this settings by editing the script file.

---

## License

Apache 2.0