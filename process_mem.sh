#!/usr/bin/env bash 
# Name: process_mem.sh
# Author: Edgar Deal - EY
# Date: 09-03-16
# Version: 1.0
# Innittab or Cron Entry: none
# Purpose: processes a memory dump using volatility, clamav and regripper
# TODO: 
#	combine some of the loops
#	more documentation
#	make the report more informative and better looking
#	maybe more modules should be used?
#	better ASCII header

# initialize sme variables
strings_state=""
module_state=""
dump_state=""
clam_state=""
regripper_state=""
virustotal_state=""
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
module_count=0
dump_count=0
clam_count=0
regripper_count=0
virustotal_count=0

# this is the awesome header, replace wit cool ASCIII later
header(){
clear
echo -e "+-+-+-+-+-+-+-+-+-+-+-+"
echo -e "|p|r|o|c|e|s|s|_|m|e|m|"
echo -e "+-+-+-+-+-+-+-+-+-+-+-+"
}

# status updates, keeps the screen clean
status(){
header
echo -e "${RED}STATUS UPDATES${NC}"
echo -e "image name \t\t ${GREEN}$image${NC}"
echo -e "image type \t\t ${GREEN}$imageinfo${NC}"
echo -e "results dir \t\t ${GREEN}$results_dir${NC}"
echo -e "report name \t\t ${GREEN}$report${NC}"
echo -e "log file \t\t ${GREEN}$log_file${NC}"
echo -e "strings \t\t ${GREEN}$strings_state${NC}"
echo -e "modules \t\t ${GREEN}$module_state${NC}"
echo -e "dumps \t\t\t ${GREEN}$dump_state${NC}"
echo -e "clamscan \t\t ${GREEN}$clam_state${NC}"
echo -e "regripper \t\t ${GREEN}$regripper_state${NC}"
echo -e "virustotal \t\t ${GREEN}$virustotal_state${NC}"
echo -e "${RED}___________________________________________________________${NC}"
echo -e "${RED}PROCESSING INFORMATION${NC}"
echo -e "\n"
}

display_usage() { 
	header
	echo "This script must be run with super-user privileges." 
	echo "Put this file in the same directoy as the memory image, then run it." 
	echo "Requires regripper, volatility, clamscan, patience." 
	echo -e "\nUsage:\n$0 [image_name]\n" 
	} 

if [  $# -lt 1 ] 
then 
	display_usage
	exit 1
fi 

if [[ ( $# == "--help") ||  $# == "-h" ]] 
then 
	display_usage
	exit 0
fi 


if [[ $USER != "root" ]]; then 
	header
	echo "This script must be run as root!" 
	exit 1
fi
 
status
#date=$(date +%Y-%m-%d_%H-%M-%S)
date=$(date +%Y-%m-%d)
updatedb
rip=$(locate rip.pl)
rip_plugins=$(locate plugins|grep ripper|head -n 1)
vol=$(which vol.py)
clamscan=$(which clamscan)
home_dir=$(pwd)
image=$1
results_dir=$date"_"$image
report=$date"_"$image".txt"
virustotal_report=$date"_"$image".csv"
log_file=$home_dir/$results_dir/$results_dir".log"

# create the results dir if it doesnt exist
if [ -d "$results_dir" ]
then
	echo results dir found, continuing analysis
else
	echo new analysis, making $results_dir
	mkdir $results_dir
fi

echo Starting log file > $log_file

# put your own VT API key here is you want
# edgar.deal@ey.com - 56a7256d1f1f6bc8cbe5b754839161b995f3ceb3767372a5b36b24343df222fa
# ragdelaed@hotmail.com - fa6d29402ff00a77d469f649c5859b4a32e30bc49a7b1ed05e6011c74bcace05
# ragdelaed01@gmail.com - e62825549e422f9449fe25e6387e8e8f83248bb5a6ca008c92af6fa9deac94a2
# ragdelaed03@gmail.com - b970b125119b2a1fb5f11baa46e71dfb92cfe0c891ba288585b431703a8e4ed2
# ragdelaed04@gmail.com	- 9d12ea288b49b8a64d7fd768c2608b78fb9cd45eaabd959d94c54ac99e25c65a
# ragdelaed05@gmail.com - a67e13243c6e3cd7a64d7497918f66431098e0ac0ef0dc36a68776850bb971cf
# ragdelaed06@gmail.com - fd354795bf158aa93c1a92e1ce18e1b81eae808ac2ce0bbe02e873fcbabe4ba9
# ragdelaed07@gmail.com - cc5b9e5951c62cbc3fa256e5445eeb8dbf4719c1e2f842604b7973c476be309d
# ragdelaed08@gmail.com - 9dbbf5034143ad92a3e7e7331c8ded63b0b48dfb695db9278147e61df35cad99

virustotal_api_key_array=(
56a7256d1f1f6bc8cbe5b754839161b995f3ceb3767372a5b36b24343df222fa
fa6d29402ff00a77d469f649c5859b4a32e30bc49a7b1ed05e6011c74bcace05 
e62825549e422f9449fe25e6387e8e8f83248bb5a6ca008c92af6fa9deac94a2
b970b125119b2a1fb5f11baa46e71dfb92cfe0c891ba288585b431703a8e4ed2
9d12ea288b49b8a64d7fd768c2608b78fb9cd45eaabd959d94c54ac99e25c65a
a67e13243c6e3cd7a64d7497918f66431098e0ac0ef0dc36a68776850bb971cf
fd354795bf158aa93c1a92e1ce18e1b81eae808ac2ce0bbe02e873fcbabe4ba9
cc5b9e5951c62cbc3fa256e5445eeb8dbf4719c1e2f842604b7973c476be309d
9dbbf5034143ad92a3e7e7331c8ded63b0b48dfb695db9278147e61df35cad99
)

virustotal_api_key_array_length=${#virustotal_api_key_array[@]}


# check to see if the imageinfo file exists so we dont have to scan for it
echo determining image type
if [ -f "$results_dir/imageinfo.txt" ]
then
	imageinfo=$(cat $results_dir/imageinfo.txt)
	status
else
	imageinfo=$($vol -f $image imageinfo|grep -i profile|awk '{print $4}'|sed 's/,//g')
	echo $imageinfo > $results_dir/imageinfo.txt
fi


status

# dump strings
if [ -f "$results_dir/strings.txt" ]
then
	strings_state="complete"
	status
else
	strings $image > $results_dir/strings.txt
	strings_state="complete"
	status
fi
status

# process mftparser special as we get mactime for this module only
echo processing $module
if [ -f $results_dir/"mftparser_mactime.txt" ]
then
	echo mftparserlooks complete, moving on
	module_count=$((module_count + 1))
	status
else
	$vol -f $image --profile=$imageinfo mftparser --output=body --output-file=mftparser.txt  2>>$log_file
	mactime -b mftparser.txt -d -z UTC > $results_dir/mftparser_mactime.csv 
	status
fi

# for each of the modules, check to see if it exists. if it doesnt, process into the results dir as a txt file
for module in netscan connections sockets sockscan psxview psscan pstree pslist malfind autoruns svcscan uninstallinfo timeliner cmdscan dyrescan envars malprocfind notepad systeminfo malfind firefoxhistory iehistory chromehistory moddump; 
do 
	echo processing $module
	if [ -f $results_dir/$module".txt" ]
	then
		echo $module looks complete, moving on
		module_count=$((module_count + 1))
		status
	else
		$vol -f $image --profile=$imageinfo $module > $results_dir/$module".txt" 2>>$log_file
		module_count=$((module_count + 1))
		module_state="completed $module_count of 25"
		status
	fi
done
module_state="complete"
status

# dump the files from the following places in memory to analyze later
echo dumping files
status
for dir in procdump dlldump dumpfiles dumpregistry screenshot malfind moddump mftparser;
do
	if [ -d "$results_dir/$dir" ]
	then
		dump_state="complete"
		dump_count=$((dump_count + 1))
		status
	else
		mkdir $results_dir/$dir
		echo dumping $dir
		dump_count=$((dump_count + 1))
		$vol -f $image --profile=$imageinfo $dir --dump-dir $results_dir/$dir 2>>$log_file
		dump_state="completed $dump_count of 6"
		status
	fi
	dump_state="complete"
	status
done


cd $home_dir/$results_dir
status

# clamAV scan the dumped directories
echo updating clamav
freshclam > $log_file 2>&1
for dir in procdump dlldump dumpfiles dumpregistry screenshot malfind moddump mftparser;
do
	if [ -f "clamscan_$dir" ]
	then
		clam_state="complete"
		clam_count=$((clam_count + 1))
		status
	else
		echo clam-scanning $dir
		clamscan -r $dir > clamscan_$dir 2>>$log_file
		clam_count=$((clam_count + 1))
		clam_state="completed $clam_count of 6"
		status
	fi
	clam_state="complete"
	status
done


cd $home_dir/$results_dir
status

# regripper all the reg files
cd dumpregistry
for reg_file in security system sam ntuser software hardware
do
	if [ -f ../regripper_$reg_file.txt ]
	then
		regripper_state="complete"
		regripper_count=$((regripper_count + 1))
		status
	else
		echo ripping $reg_file
		$rip -r $(ls|grep -i $reg_file|grep -v txt) -f $reg_file > ../regripper_$reg_file.txt 2>>$log_file
		regripper_count=$((regripper_count + 1))
		regripper_state="completed $regripper_count of 6"
		status
	fi
	regripper_state="complete"
	status
done

# this part takes the longest so i only included the dump files that would yield the results.
cd $home_dir/$results_dir
status
for dir in malfind moddump mftparser dlldump;
do
	if [ -f  virustotal_$dir.csv ]
	then 
		virustotal_state="$dir is complete"
		virustotal_count=$((virustotal_count + 1))
		status
	else
		echo "Search Term;Requested;Response;Scan Date;Detections;Total;Permalink;AVs;CVEs" > virustotal_$dir.csv
		virustotal_dir_count=$(ls $dir|wc -l)
		echo processing $dir with virustotal
		for file in `ls -1 $dir/*`
		do
			echo looking for $file files
			rand=$[$RANDOM % $virustotal_api_key_array_length]
			key=${virustotal_api_key_array[$rand]}
			echo trying key $key on file $file
			timeout 120 virustotal-search.py  -k $key -m $file >> virustotal_$dir.csv 2>>$log_file
			virustotal_count=$((virustotal_count + 1))
			virustotal_state="completed $virustotal_count of $virustotal_dir_count for $dir"
			sleep 2
			rm -f virustotal-search*.csv
			status
		done
		virustotal_count=0
		virustotal_state=complete
		status
	fi	
done
rm -f virustotal-search*.csv
rm -f virusttoal-search.pk1

# make a pretty txt file report. (still needs work on the pretty part)
status
cd $home_dir/$results_dir
echo VIRUSTOTAL RESULTS > $report
echo ___________________________________________________________ >> $report
echo "Search Term;Requested;Response;Scan Date;Detections;Total;Permalink;AVs;CVEs" > $virustotal_report
egrep -H -v ";;|VTHTTPReportRequest|requested resource|Search Term" virustotal* >> $virustotal_report
echo please review $virustotal_report >> $report
echo -e "\n" >> $report
echo CLAMSCAN RESULTS >> $report
echo ___________________________________________________________ >> $report
egrep -H -v "OK|^$" clamscan_*|egrep -v "SCAN|Known|Engine|Scanned|Data|Time|Infected|Empty" >> $report
echo -e "\n" >> $report
echo MODULES RESULTS >> $report
echo ___________________________________________________________ >> $report
grep ABNORMAL malprocfind.txt >> $report

echo -e "\n"
echo "report is stored at $results_dir"/"$report"
