#!/bin/bash

# alligator - All in one Android binary manipulation tool 
# This file is part of alligator Project
# Written by: @lamhacker
# Website: https://www.twelvesec.com/
# GIT: https://github.com/twelvesec/TODO
# TwelveSec (@Twelvesec)
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful,but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.For more see the file 'LICENSE' for copying permission.


####################################################################################
# Credit for certificate pinning: https://omespino.com/tutorial-universal-android-ssl-pinning-in-10-minutes-with-frida/
# Credit for certificate pinning: https://github.com/iSECPartners/Android-SSL-TrustKiller/releases/
# Credit for certificate pinning: https://cooltrickshome.blogspot.com/2018/11/ssl-pinning-bypass-on-android-emulator.html?spref=tw
# Credit for certificate pinning: http://www.security-assessment.com/files/documents/whitepapers/Bypassing%20SSL%20Pinning%20on%20Android%20via%20Reverse%20Engineering.pdf
# Credit for certificate pinning: https://blog.netspi.com/four-ways-bypass-android-ssl-verification-certificate-pinning/
####################################################################################

####################################################################################
# Adding ASCI ART
####################################################################################

 base64 -d <<< "X19fX19fX19fX18gICAgICAgICAgICAgIC5fXyAgICAgICAgICAgICAgICBfX19fX19fX18gICAgICAgICAgICAgIApcX18gICAgX19fL18gIF8gIF9fIF9fX18gfCAgfF9fXyAgX18gX19fXyAgLyAgIF9fX19fLyBfX19fICAgX19fXyAgCiAgfCAgICB8ICBcIFwvIFwvIC8vIF9fIFx8ICB8XCAgXC8gLy8gX18gXCBcX19fX18gIFxfLyBfXyBcXy8gX19fXCAKICB8ICAgIHwgICBcICAgICAvXCAgX19fL3wgIHxfXCAgIC9cICBfX18vIC8gICAgICAgIFwgIF9fXy9cICBcX19fIAogIHxfX19ffCAgICBcL1xfLyAgXF9fXyAgPl9fX18vXF8vICBcX19fICA+X19fX19fXyAgL1xfX18gID5cX19fICA+CiAgICAgICAgICAgICAgICAgICAgICAgXC8gICAgICAgICAgICAgICBcLyAgICAgICAgXC8gICAgIFwvICAgICBcLyA="


printf "\n"
printf "By Lamehacker -- Free Industries\n"
printf "\n"

###################################################################################
# Setting colors
###################################################################################

YELLOW='\033[0;33m' # Errors
CYAN='\033[0;36m' # Info
PURPLE='\033[0;35m' # Tips
RED='\033[0;31m' # Success
NC='\033[0m' # No Color

##################################################################################
# Checking prerequisite
###################################################################################

check_prerequisites() {

	printf  "${CYAN} Checking prerequisites....${NC} \n"

	###################################################################################
	# Check for android-tools-adb and android-tools-fastboot
	###################################################################################

	if ! dpkg-query -l adb  > /dev/null; then

           printf "${YELLOW}android-tools not found! Install? (y/n)${NC}\c"
	   read

	   if "$REPLY" = "y"; then

		printf "${CYAN}Installing adb tools using apt-get...${NC} "
		sudo apt-get update -y
		sudo apt-get install android-tools-adb android-tools-fastboot
	   fi

	else
       		printf "${RED}--- ADB tools installed ---${NC}\n"	
	fi


	###################################################################################
	# Check if apksigner exists
	###################################################################################

	if ! dpkg-query -l apksigner  > /dev/null; then
	   
		printf "${YELLOW}Android-tools not found! Install? (y/n)${NC} \c"
		read

	   if "$REPLY" = "y"; then

	        printf "${CYAN}Installing apksigner tools using apt-get...${NC}\n"
		sudo apt-get update -y
	        sudo apt-get install apksigner
	   fi

	else 
		printf "${RED}--- APKSigner is installed ---${NC}\n"

	fi

        ###################################################################################
        # Check if openssl exists
        ###################################################################################

        if ! dpkg-query -l openssl  > /dev/null; then

                printf "${YELLOW}Openssl not found! Install? (y/n)${NC}\n \c"
                read

           if "$REPLY" = "y"; then

                printf "${CYAN}Installing openssl using apt-get...${NC}\n"
                sudo apt-get update -y
                sudo apt-get install openssl
           fi

        else
		
                printf "${RED}--- Openssl is installed ---${NC}\n"

        fi

	####################################################################################
	# Check if keystore exists
	####################################################################################

	FILE=/usr/bin/keytool

	if test -f "$FILE"; then

	    	printf "${RED}--- Keytool is installed ---${NC}\n"
	else 

		printf "${YELLOW}--- Install Keytool ---${NC}\n"

	fi

	####################################################################################
	# Check if aapt exists
	####################################################################################

	FILE=/usr/bin/aapt

	if test -f "$FILE"; then

		printf "${RED}--- aapt is installed ---${NC}\n"

	else 

		printf "${YELLOW}--- Install aapt (should be installed with adb) ---${NC}\n"

	fi

	###################################################################################
	# Check for apktool install path
	###################################################################################

	FILE=/usr/local/bin/apktool

	if test -f "$FILE"; then

		printf "${RED}--- Apktool is installed ---${NC}\n"

	else 

		printf "${YELLOW}---- Install Apktool ---${NC}\n"

	fi

	return 0
}

decode_apk() {

	now=$(date +"%T")
	
	printf "${CYAN}Decoding/unziping APK file...${NC} \n"

	error=$(apktool d $1 -o decoded 2>&1 1>/dev/null)

	if [ $? -eq 0 ]; then
		
		printf "${RED}APK successfully decoded (output file name decoded) ${NC} \n"

	else
             printf "${YELLOW}APK not decoded see error: ${NC}\n\n $error"

	     return 1
      	fi

	printf "${CYAN}Running static analysis${NC} \n"

	printf "${CYAN}Creatng file named info to print data...${NC} \n"

	printf "Tip:${PURPLE} Edit the regex expressions to search the app ${NC}\n"

	touch info.txt
      
	chmod +rw info.txt
     
	echo "----------------Time: $now - Collecting sensetive information from APK ----------------" >> info.txt

	aapt dump permissions $1 >> info.txt
        echo "-----------------------------------------" >> info.txt
	aapt dump badging $1 >> info.txt
        echo "-----------------------------------------" >> info.txt
	aapt list -v $1 >> info.txt 
	echo "-----------------------------------------" >> info.txt
	
	echo "--- Searching hidden usernames ---" >> info.txt
	echo "-----------------------------------------" >> info.txt
	egrep -Rw "username" decoded >> info.txt
	
	echo "--- Searching hidden passwords ---" >> info.txt
        echo "-----------------------------------------" >> info.txt
	egrep -Rw "password" decoded >> info.txt

	echo "--- Searching anti-tamper controls ---" >> info.txt
        echo "-----------------------------------------" >> info.txt
	egrep -Rw "tamper" decoded >> info.txt
	egrep -Rw "TamperCheck" decoded >> info.txt

        echo "--- Searching for certificate pinning controls ---" >> info.txt
        echo "-----------------------------------------" >> info.txt
        egrep -Rw "pinning" decoded >> info.txt
	egrep -Rw "CertificatePinner" decoded >> info.txt # Pinning with OkHttp
	egrep -Rw "certPinner" decoded >> info.txt # Pinning with OkHttp
	egrep -Rw "addConverterFactory" decoded >> info.txt # Pinning with Retrofit
	egrep -Rw "Picasso.Builder(getApplicationContext" decoded >> info.txt # Pinning with Picasso
	egrep -Rw "validatePinning" decoded >> info.txt # Pinning with HttpUrlConnection 
	egrep -Rw "X509TrustManagerExtensions" decoded >> info.txt # Pinning with HttpUrlConnection 
	egrep -Rw "validPins" decoded >> info.txt # Pinning with HttpUrlConnection 
	egrep -Rw "SHA-256" decoded >> info.txt # Generic pinners
	egrep -Rw "pin" decoded >> info.txt # Generic pinners
	egrep -Rw "SHA-256" decoded >> info.txt # Generic pinners
	egrep -Rw "pinningHostnameVerifier" decoded >> info.txt # Pinning with Apache HttpClient
	egrep -Rw "PinningHostnameVerifier" decoded >> info.txt # Pinning with Volley

	
	echo "---Searching hidden URLs ---" >> info.txt
        echo "-----------------------------------------" >> info.txt
	egrep -Rw '(http|https)://[^/"]+' decoded >> info.txt
	
	echo "---Searching SSL config  ---" >> info.txt
        echo "-----------------------------------------" >> info.txt
	egrep -Rw "SSL decoded" decoded >> info.txt
	egrep -Rw "CERTIFICATES_CHAIN" decoded >> info.txt
	egrep -Rw "CertificatePinning" decoded >> info.txt
	egrep -Rw "const-string" decoded >> info.txt
	egrep -Rw "Security" decoded >> info.txt
	
	printf "${RED}Static analysis finished...\n${NC}"

        printf "${CYAN}Extracting CERT.RSA from APK to working directory ${NC}\n"

        cp decoded/original/META-INF/CERT.RSA  $PWD

        printf "${CYAN}Converting CERT.RSA from APK to readable format ${NC}\n"

        openssl pkcs7 -inform DER -print_certs -out extracted_cert.pem -in CERT.RSA

        printf "${CYAN}Extracting public key from original certificate to readable format ${NC}\n"

        openssl x509 -pubkey -noout -in extracted_cert.pem  > pubkey.pem

        printf "${RED}Success APK certificate publick key extracted ${NC}\n"

	return 0

}

sign_apk() {
	
        #########################################################################
        # Attempt to sign the APK
        #########################################################################

        printf "Tip:${PURPLE}Use keytool -genkey -alias appdomain -keyalg RSA -keystore alligator.ks -keysize 2048 to generate the keystore${NC}\n"
	printf "Tip:${PURPLE}Make sure to create in advance your keystore, before executing this command ${NC}\n"

        printf "${CYAN}Attempt to sign the APK ${NC}\n"

	FILE=$PWD/alligator.ks

        if test -f "$FILE"; then
		apksigner sign --ks alligator.ks $1
		apksigner verify --verbose aligned_encoded.apk
		mv aligned_encoded.apk signed_aligned_encoded.apk
                printf "${RED}Success APK named signed_aligned_encoded.apk signed and verified${NC}\n"
		return 0
        else

                printf "${YELLOW}--- alligator.ks keystore does not exist ---${NC}\n"
		printf "${YELLOW}--- Create alligator.ks using keytool,---${NC}\n"
		printf "${PURPLE}--- Run: keytool -genkey -alias appdomain -keyalg RSA -keystore alligator.ks -keysize 2048 to generate the keystore ---${NC}\n"
		return 1

        fi
}

build_apk() {

        now=$(date +"%T")

        printf  "${cyan}Building/ziping APK file, time is  $now, do not sleep the Bogeyman is coming ${NC}\n"

	#########################################################################
	# 1st Attempt to build the APK
	#########################################################################
	
	printf "${CYAN}First attempt to build the APK ${NC}\n"

        error=$(apktool b $1 -o encoded.apk 2>&1 1>/dev/null)

        if [ $? -eq 0 ]; then

                printf "${RED}APK successfully build see output file name encoded.apk ${NC}\n"
                printf "${CYAN}Running zipalign ${NC}\n"
                zipalign 4 encoded.apk aligned_encoded.apk
		printf "${RED}APK aligned_encoded.apk generated ${NC}\n"

		return 0
        else
             printf "\n\n${YELLOW}APK not build see error: ${NC}\n $error \n\n"
        fi


        #########################################################################
        # 2nd Attempt to build the APK
        #########################################################################

	printf "${CYAN}Second attempt to build the APK ${NC}\n"
	
	mkdir empty_dir

        error=$(apktool -p empty_dir b $1 -o encoded.apk 2>&1 1>/dev/null)

        if [ $? -eq 0 ]; then

                printf "${RED}APK successfully buildded see utput file name encoded.apk ${NC}\n"
                printf "${CYAN}Deleting temp folders${NC}\n"
                rm -fr empty_dir
                printf "${CYAN}Running zipalign${NC}\n"
                zipalign 4 encoded.apk aligned_encoded.apk
		printf "${RED}APK aligned_encoded.apk generated ${NC}\n"

		return 0
        else
             printf "\n\n${YELLOW}APK not build see error: ${NC} \n\n $error \n\n"
        fi

        #########################################################################
        # 3rd Attempt to build the APK
        #########################################################################

	printf "${CYAN}Third attempt to build the APK ${NC}\n"

        error=$(apktool -p empty_dir --use-aapt2 b $1 -o encoded.apk 2>&1 1>/dev/null)

        if [ $? -eq 0 ]; then

                printf "${RED}APK successfully build see output file name encoded.apk ${NC}\n"
		printf "${CYAN}Deleting temp folders${NC}\n"
		rm -fr empty_dir
		printf "${CYAN}Running zipalign${NC}\n"
		zipalign 4 encoded.apk aligned_encoded.apk
		printf "${RED}APK aligned_encoded.apk generated ${NC}\n"

		return 0
        else
             printf "\n\n${YELLOW}APK not build see error: ${NC} \n\n $error\n\n"
	     printf "${CYAN}Try manual building...${NC}\n"
	     rm -fr empty_dir

	     return 1
        fi
}


dynamic_analysis() {

	# Start adb server 
	adb kill-server
	adb start-server
	adb forward tcp:31415 tcp:31415 # Setup Drozer for proxy

	# Start seperate terminal
	konsole --noclose -e "adb shell" &
	konsole --noclose -e "adb logcat" &
	konsole --noclose -e "drozer console connect" &

	return 0
}

clean_garbage() {

	printf "${CYAN}Cleaning test files for a new start...${NC}\n"

	#############################################################################

  	DIR="$PWD/decoded"
	
        if [ -d "$DIR" ]; then

		rm -fr decoded
                printf "${RED}--- decoded folder is  deleted ---${NC}\n"

        else

                printf "${YELLOW}---- decoded folder does not exist ---${NC}\n"

        fi
	
	#############################################################################

        DIR="$PWD/empty_dir"

        if [ -d "$DIR" ]; then

                rm -fr empty_dir/
                printf "${RED}--- empty_dir folder is  deleted ---${NC}\n"

        else

                printf "${YELLOW}---- empty_dir folder does not exist ---${NC}\n"

        fi

	#############################################################################

        FILE=$PWD/info.txt

        if test -f "$FILE"; then

                rm -f info.txt
                printf "${RED}--- info.txt file is  deleted ---${NC}\n"

        else

                printf "${YELLOW}---- info.txt file does not exist ---${NC}\n"

        fi

	#############################################################################

        FILE=$PWD/encoded.apk

        if test -f "$FILE"; then

                rm -f encoded.apk
                printf "${RED}--- encoded.apk file is  deleted ---${NC}\n"

        else

                printf "${YELLOW}---- encoded.apk file does not exist ---${NC}\n"

        fi

	#############################################################################

        FILE=$PWD/aligned_encoded.apk

        if test -f "$FILE"; then

                rm -f aligned_encoded.apk
                printf "${RED}--- aligned_encoded.apk file is  deleted ---${NC}\n"

        else

                printf "${YELLOW}---- aligned_encoded.apk file does not exist ---${NC}\n"

        fi

	#############################################################################

        FILE=$PWD/CERT.RSA

        if test -f "$FILE"; then

                rm -f CERT.RSA
                printf "${RED}--- CERT.RSA file is  deleted ---${NC}\n"

        else

                printf "${YELLOW}---- CERT.RSA file does not exist ---${NC}\n"

        fi

	#############################################################################

        FILE=$PWD/extracted_cert.pem

        if test -f "$FILE"; then

                rm -f extracted_cert.pem
                printf "${RED}--- extracted_cert.pem file is  deleted ---${NC}\n"

        else

                printf "${YELLOW}---- extracted_cert.pem file does not exist ---${NC}\n"

        fi

	#############################################################################

        FILE=$PWD/pubkey.pem

        if test -f "$FILE"; then

                rm -f pubkey.pem
                printf "${RED}--- pubkey.pem file is  deleted ---${NC}\n"

        else

                printf "${YELLOW}---- pubkey.pem file does not exist ---${NC}\n"

        fi
		
	printf "${CYAN}Deleted all test files ${NC}"

}


print_help() {

	printf "Script usage:\n"
        printf "\n"
        echo "-h  option: Print this message."
        echo "-d  option: Decode/unzip the apk and dump info such as passwords,  permissions and URLs."
        echo "-c  option: Check all prerequisites are installed."
        echo "-b  option: Build/encode the apk from the folder supplied."
        echo "-s  option: Sign the target using your keystore apk, rename your keystore file to alligator_Keystore.ks."
        echo "-a  option: Attempts to start adb server, shell, logcat and drozer console in seperate terminals."
        echo "-r  option: Deletes directory decoded,directory empty_dir, and files encoded.apk,aligned_encoded.apk."
        printf "\n"
        printf "Examples:\n"
        printf "\n"
        echo "How to use: 1st decode the APK -> 2nd Do manual edit -> 3rd Build APK and 4th Sign APK"
        echo "Decoding an apk: ./aligator.sh -d target_apk.apk"
        echo "Building an apk: ./aligator.sh -b target_apk_folder"
        echo "Signing an apk: ./aligator.sh -s yourkeystore.ks target_apk.apk"
        echo "Assesing dynamically the apk: ./alligator.sh -a"
        echo "Deleting generated files: ./alligator.sh -r"

}

###################################################################################
# Run script normally 
##################################################################################

while getopts 'rahcd:b:s:' OPTION; do

	case "$OPTION" in

		d)

			decode_apk $OPTARG
			exit 1
			;;
		c)
		        check_prerequisites
			exit 1
			;;

		b)       
			build_apk $OPTARG
			exit 1
			;;

		s)	
			sign_apk $OPTARG
			exit 1
			;;
		
		a)
			dynamic_analysis
			exit 1
			;;

		r)	
			clean_garbage
			exit 1
			;;

		h)
			print_help $OPTARG
			exit 1
			;;

		?)

			echo "Invalid command, please try again"
			;;
	esac
done

shift "$((OPTIND-1))"
