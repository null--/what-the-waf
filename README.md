Find a way to bypass that bloody WAF.  
-- A Burp 1.6+ Extension  

#A WAF Story
###In WAF we trust
[Tom is very happy because he configured a WAF for Lisa's website.  
He told Lisa that their website is secure now and Blackhat can no longer hack them.]  
Tom: Look at my big white WAFstick!  
Lisa: Holy WAF!  
Blackhat (whisper to himself while sneaking around): WAF! that hurts.  
Lisa: Tom, you WAF like bunnies!  
Blackhat (whisper to himself): Just wait for the time when the shit hits the WAF, sweety!  
Tom (notices Blackhat and says): Why don't you go outside and play hide-and-go-WAF-yourself?  
Blackhat: When inserting your WAFstick into your own anal cavity, take great precaution not to injure yourself.   
Blackhat (looking at Lisa): And nice WAFing tits, by the way!  
[Blackhat leaves them alone and fires up his "What the WAF?!"]  
[End of Story]

#Features
1. Advanced options to pentest worldclass WAFs  
2. Sophisticated payloads  
3. Save test resluts and open them in a spreadsheet software  
4. Empower the mighty Burp  

#Installation
Download jruby-complete jar file from [JRuby](http://www.jruby.org/download)  
Copy "bapps/" to "<path>/<to>/<burp>/bapps/"
Open your "Burp Suite"  
Go to "Extender"  
Go to "Options"  
On "Ruby Environment" section set "Location of JRuby JAR file" to "\[foo\]/\[bar\]/jruby-complete-\[version\].jar"  
Go to "Extensions"  
Click on "Add"  
Set "Extension Type" to "Ruby"  
Click on "Select File" and choose "\[foo\]/\[bar\]/what-the-waf.rb"  

# Case Study and Examples
### example/General
WTW 101  

### example/Fortiweb
Configure Burp and WTW to pentest a FortiWeb WAF (real-world case-study)  

### example/Chart
How to draw a chart from a saved result  

# Usage
Please take a look at "Readme" tab in the "What the WAF?!" extension tab in Burp.  
You can find useful informations about how to use WTW and what are its limitations.  

#Test Environment
jruby-complete.jar Version: 1.7.15  
local jruby version: 1.5.6  
OS: Debian Jessie  
