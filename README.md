# kobackupdec.NET
HUAWEI backup decryptor in C#

<a href="https://consumer.huawei.com/minisite/HiSuite/HiSuite_en/index.html">
<img src="https://consumer-img.huawei.com/content/dam/huawei-cbg-site/en/support/hisuite/img/s1-pic.png" width="330" height="300" align="right"/></a>

The original [kobackupdec](https://github.com/RealityNet/kobackupdec) is a Python3 script aimed to decrypt [HUAWEI HiSuite](https://consumer.huawei.com/en/support/hisuite/) or [KoBackup](https://play.google.com/store/apps/details?id=com.huawei.KoBackup) (the Android app) backups. 
Here it is my "porting" in .NET, credit goes to [dfirfpi](https://github.com/dfirfpi) for its original idea and implementation.

For any further information, please read:
* the blog post at https://blog.digital-forensics.it/2019/07/huawei-backup-decryptor.html
* the [kobackupdec](https://github.com/RealityNet/kobackupdec) script for Python3

## Usage

The [original script](https://github.com/RealityNet/kobackupdec) *assumes* that backups are encrypted with a user-provided password. Actually it does not support the HiSuite _self_ generated password when the user does not provide its own.

```
usage: kobackupdec.exe password backup_path dest_path

  password       user password for the backup
  backup_path    backup folder
  dest_path      decrypted backup folder
```

- `password`, the user provided password.
- `backup_path`, the folder containing the HUAWEI backup, relative or absolute paths can be used. **Be careful** to provide the strictest path to data, because the script will start enumerating all files and folders starting from the provided path, parsing the file types it expects to find and copying out all the others. If by chance you wrongly provide *C:\\* as the backup path, well, expect to get a full volume copy in the destination folder (ignoring errors).
- `dest_path`, the folder to be created in the specified path, absolute or relative. It will complain if the provided folder already exists.

### Example

```
Z:\> kobackupdec.exe password "Z:\HUAWEI P30 Pro_2019-06-28 22.56.31" Z:\HiSuiteBackup
```

As the [original script](https://github.com/RealityNet/kobackupdec), the **output** folder structure will be similar to the following one: *data/data* applications will be exploded in their proper paths, and the APKs will be *restored* too (not icons, actually). Note that the **db** folder will contain the *special* databases as created by your backup.

<a href="https://www.sqlite.org/">
<img src="https://www.sqlite.org/images/sqlite370_banner.gif" align="right"/></a>

Database uses [SQLite format 3](https://www.sqlite.org/version3.html), see also https://sqliteonline.com/ for an online browser but remember **it contains your sensitive and personal data**.

```
HiSuiteBackup
|-- data
|   |-- app
|   |   |-- de.sec.mobile.apk-1
|   |   | [...]
|   |   `-- org.telegram.messenger.apk-1
|   `-- data
|       |-- de.sec.mobile
|       | [...]
|       `-- org.telegram.messenger
|-- db
|   |-- alarm.db
|   |-- contact.db
|   |-- calendar.db
|   |-- camera.db
|   |-- clock.db
|   |-- harassment.db
|   |-- HWlanucher.db
|   |-- phoneManager.db
|   |-- sms.db
|   |-- sns.db
|   |-- weather.db
|   `-- wifiConfig.db
`-- storage
    |-- Alarms
    |-- DCIM
    |-- Download
    |-- Music
    |-- Notifications
    |-- Pictures
    |-- Ringtones
    |-- WhatsApp
    `-- s8-wallpapers-9011.PNG
```

