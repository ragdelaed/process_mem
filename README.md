# process_mem

processes a memory dump using volatility, clamav, virustotal and regripper

point this at the memory dump.
add your own virustotal keys in the code, or use mine.
the script will grab these from volatility first:
	netscan 
	connections 
	sockets 
	sockscan 
	psxview 
	psscan 
	pstree 
	pslist 
	malfind 
	autoruns 
	svcscan 
	uninstallinfo 
	timeliner 
	cmdscan 
	dyrescan 
	envars 
	malprocfind 
	notepad 
	systeminfo 
	malfind 
	firefoxhistory 
	iehistory 
	chromehistory 
	moddump

then it dumps any files found in these:
	procdump 	
	dlldump 
	dumpfiles 
	dumpregistry 
	screenshot 
	malfind 
	moddump 
	mftparser

then it updates clamav, then scans all files in these directories:
	procdump 
	dlldump 
	dumpfiles 
	dumpregistry 
	screenshot 
	malfind 
	moddump 
	mftparser

then it regrips all these hives:
	security 
	system 
	sam 
	ntuser 
	software 
	hardware

then it looks up the md5 on virustotal for any file in these directories:
	malfind 
	moddump 
	mftparser 
	dlldump

it then makes a "report" and all findings are gathered into one CSV

