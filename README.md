# kobackupdec.NET
HUAWEI backup decryptor in C#

The original [kobackupdec](https://github.com/RealityNet/kobackupdec) is a Python3 script aimed to decrypt [HUAWEI HiSuite](https://consumer.huawei.com/en/support/hisuite/) or [KoBackup](https://play.google.com/store/apps/details?id=com.huawei.KoBackup) (the Android app) backups. 
Here it is my "porting" in .NET

For any further information, please read:
* the blog post at https://blog.digital-forensics.it/2019/07/huawei-backup-decryptor.html
* the [kobackupdec](https://github.com/RealityNet/kobackupdec) script for Python3

## Usage

The [original script](https://github.com/RealityNet/kobackupdec) *assumes* that backups are encrypted with a user-provided password. Actually it does not support the HiSuite _self_ generated password, when the user does not provide its own.

```
usage: kobackupdec.exe password backup_path dest_path

positional arguments:
  password       user password for the backup
  backup_path    backup folder
  dest_path      decrypted backup folder
```

- `password`, the user provided password.
- `backup_path`, the folder containing the HUAWEI backup, relative or absolute paths can be used. **Be careful** to provide the strictest path to data, because the script will start enumerating all files and folders starting from the provided path, parsing the file types it expects to find and copying out all the others. If by chance you wrongly provide *c:\\* as the backup path, well, expect to get a full volume copy in the destination folder (ignoring errors).
- `dest_path`, the folder to be created in the specified path, absolute or relative. It will complain if the provided folder already exists.

### Example

As the [original script](https://github.com/RealityNet/kobackupdec), the **output** folder structure will be similar to the following one: *data/data* applications will be exploded in their proper paths, and the APKs will be *restored* too (not icons, actually). Note that the **db** folder will contain the *special* databases as created by your backup.

Databases use [SQLite format 3](https://www.sqlite.org/version3.html), see also https://sqliteonline.com/ for an online browser.

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
|   |-- HWlanucher.db
|   |-- Memo.db
|   |-- alarm.db
|   |-- calendar.db
|   |-- calllog.db
|   |-- camera.db
|   |-- clock.db
|   |-- contact.db
|   |-- harassment.db
|   |-- phoneManager.db
|   |-- setting.db
|   |-- sms.db
|   |-- soundrecorder.db
|   |-- systemUI.db
|   |-- weather.db
|   `-- wifiConfig.db
`-- storage
    |-- DCIM
    |-- Download
    |-- Huawei
    |-- MagazineUnlock
    |-- Notifications
    |-- Pictures
    |-- WhatsApp
    |-- mp3
    |-- parallel_intl
    `-- s8-wallpapers-9011.PNG
```

