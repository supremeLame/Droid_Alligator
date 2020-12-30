![Image](https://d1yjjnpx0p53s8.cloudfront.net/daligator_converted-01.png "icon")

Droid_Alligator-v1.0
======
**Droid_Alligator-1.0** is a bash script for android exploration, built to help you assess the security posture of your android mobile applications, without needing a jailbreak. More specifically it does the following thinks:

1. Decode/unzip the apk and dump info such as passwords,  permissions and URLs.
2. Build/encode the apk from the folder supplied.
3. Sign the target android application using your keystore apk (you have to rename your keystore file to alligator_Keystore.ks).

## Download
* [Version 1.0](https://github.com/supremeLame/Droid_Alligator.git)

## Usage
---
```
$ git clone https://github.com/supremeLame/Droid_Alligator.git
$ chmod +x Droid_alligator_v1.0.sh
$ Droid_alligator_v1.0.sh -h
___________              .__                _________              
\__    ___/_  _  __ ____ |  |___  __ ____  /   _____/ ____   ____  
  |    |  \ \/ \/ // __ \|  |\  \/ // __ \ \_____  \_/ __ \_/ ___\ 
  |    |   \     /\  ___/|  |_\   /\  ___/ /        \  ___/\  \___ 
  |____|    \/\_/  \___  >____/\_/  \___  >_______  /\___  >\___  >
                       \/               \/        \/     \/     \/ 
By Lamehacker -- Free Industries

Script usage:

-h  option: Print this message.
-d  option: Decode/unzip the apk and dump info such as passwords,  permissions and URLs.
-c  option: Check all prerequisites are installed.
-b  option: Build/encode the apk from the folder supplied.
-s  option: Sign the target using your keystore apk, rename your keystore file to alligator_Keystore.ks.
-a  option: Attempts to start adb server, shell, logcat and drozer console in seperate terminals.
-r  option: Deletes directory decoded,directory empty_dir, and files encoded.apk,aligned_encoded.apk.

Examples:

How to use: 1st decode the APK -> 2nd Do manual edit -> 3rd Build APK and 4th Sign APK
Decoding an apk: ./aligator.sh -d target_apk.apk
Building an apk: ./aligator.sh -b target_apk_folder
Signing an apk: ./aligator.sh -s yourkeystore.ks target_apk.apk
Assesing dynamically the apk: ./alligator.sh -a
Deleting generated files: ./alligator.sh -r
```
1. Decode the APK using the -d option
2. Manually edit the APK
3. Build the apk using the -b option
4. Sign the apk using the -s option

## Contributors
---
supremeLame

## Version 
---

* Version 1.0

## Contact
---

* Blog page: https://securityhorror.blogspot.com/
