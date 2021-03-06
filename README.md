# BBS Volatile IDS

NOTE: I added a fatal bug to the program a couple weeks ago. The bug is now fixed, but the program is still not done. I'm hoping version 1.0 will be complete this week. I am a full time student, and I work 19 hours a week. Once I get all the bugs worked out, I'll probably upload a version of the program with the correct directory structure.

BBS Volatile IDS looks through memory dumps for malware and prints an easy to read report about the memory dump. According to a malware expert from the NSA, the program catches over 95% of malware. The 5% of malware that the program does not immediately catch can be found by looking at suspicious indicators in the report and examining the memory dump based on what you find.

This program uses the Volatility Framework. Without the people that contributed in developing Volatility, I could have never written this program. I didn't do the hard work, they did. All I did was run their programs and parse the data (after intensely reading a very large intimidating book "The Art of Memory Forensics"). You would not believe how much work the people at Volatility (I think one of the guys worked at Google) did to make this program possible. I am a very basic programmer. The only reason this program is good is because I used other people's YEARS of work. That's the best thing about programming, all you have to do is find someone better than you and use their work. Seriously... there are probably 100 people that have contributed to volatility. The vast majority of this program was not written by me.

This program also uses a ton of people's yara rules. I'm not going to name them, but their rules are what make this program awesome. If you have yara rules I don't use, SUBMIT YOUR RULES TO ME!!! I would love to use your rules to make this program better. 

Open Source Software is so AWESOME!!! 

See INSTALLATIONINSTRUCTIONS.txt for information on compiling the program. 

# Important Information

IMPORTANT: If you want to use this program, you need to fix the directory structure of change the packages. I'm not very good with github so I don't know how to change directory structures on here.

NOTE:
bigbrainsecurity.jar must be placed in the volatility directory for the program to work. 
- Create this file from the commandline by typing ~$ sbt assembly

bbs_config.txt contains the information the program uses to run. If you don't fill it out, the program won't work. 

user_config.txt is created if you use the kdbg as an argument. Don't delete it. It will overwrite itself.

COMING SOON:
- Create regex in txt file for use when filtering MFT and timeliner.
- Separate files will be created with svcscan split up into different sections (e.g. stopped services, running services)
- File Clean Up: Will get rid of all the extra junk in the volatility directory so it doesn't get cluttered.
- Some of the scans will be written to text files (e.g. envars)
- Program will run scans that block at the beginning of the program and then use futures to multithread processing.
--- svcscan takes forever to run because the data was difficult to parse. 
- Event log and mft extraction will be moved to after the report is created.
- GeoIP Database lookup for foreign IPv4 addresses.
- I have a list of things I want to add in my code (like hollowfind). I think a lot of the programs will be run after the report is written (like extracting event logs and mfts).
- Wiki describing programs used. 
- Some parts of program are a little bit too verbose. 
- Allow users to add their own yara files.
- Parse all yara output into the same kind of object.
- I just started learning about volatility at the beginning of the summer so I'll be adding a lot more to the program next semester.

DISTANT FUTURE:
- A basic GUI so users can determine the volatility directory, the memory dump, the os version, and the kdbg. 

CURRENT ISSUES:
- I never re-fixed connscan so Windows XP and Server 2003 won't parse correctly. (It used to work back when I only included the destination IP addresses. I haven't tested the updated style of parsing when looking for IP addresses in DLL ranges with yara).
- There's a bug with exploitkits_rules.yar results parsing. I'll fix it soon probably. 
- The risk rating sucks so I'm not going to use it until it's fixed.
- The directory structure on github is not the same as my directory structure on my computer.
- I'm pretty sure I overused the Try object to make sure the program makes it through any memory dump.
- Some of the method and variable names need to be changed to make code easier to read (e.g. verb noun, noun).
