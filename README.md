Find a way to bypass that WAF
-- A Burp 1.6+ Extension  

#Info
Latest Version: 1.4 (beta)  
Current BApp Store Version: 1.4 (beta)  

#A WAF Story
###In WAF we trust
[Tom is very happy because he configured a WAF for Lisa's website.  
He told Lisa that their website has been secured and Mr. "Blackhat" cannot hack them, anymore]  
  
Tom: Look at my big white WAFstick!  
Lisa: Holy WAF!  
Blackhat (whispering to himself while sneaking around): WAF?! that hurts.  
Lisa: Tom, You WAF, like bunnies!  
Blackhat (whispering to himself): Just wait for the time when the shit hits the WAF, sweety!  
Tom (notices Blackhat and says): Why don't you go outside and play hide-and-go-WAF-yourself?  
Blackhat: Calm down tommy! When inserting your WAFstick into your own a**l cavity, take great precaution not to injure yourself.   
Blackhat (looking at Lisa then says): And, nice WAFing t*ts, by the way!  
[Blackhat leaves them alone and fires up his "What the WAF?!"]  
[End of Story]

#Features
1. Advanced options to pentest worldclass WAFs  
2. Sophisticated payloads  
3. Save test resluts and open them in a spreadsheet software  
4. Empower the mighty Burp  

#Installation
## Pre-Installation
Download jruby-complete jar file from [JRuby](http://www.jruby.org/download)  
Go to "Extender"  
Go to "Options"  
On "Ruby Environment" section set "Location of JRuby JAR file" to "\[foo\]/\[bar\]/jruby-complete-\[version\].jar"  

## Installation: Using BApp Store
Go to "Extension" > "BApp Store"  
Find "What-The-WAF" and install it  

## Installation: Manual
Copy "bapps/" to "<path>/<to>/<burp>/bapps/"
Open your "Burp Suite"  
Go to "Extensions"  
Click on "Add"  
Set "Extension Type" to "Ruby"  
Click on "Select File" and choose "\[foo\]/\[bar\]/what-the-waf.rb"  

# Case Study and Examples
### Path: example/General
WTW 101  

### Path: example/Fortiweb
Configure Burp and WTW to pentest a FortiWeb WAF (real-world case-study)  

### Path: example/Chart
How to draw a chart from a saved result  

# Usage
Please take a look at "Readme" tab in the "What the WAF?!" extension tab inside Burp.  
You can find useful informations about how to use WTW and what are its limitations.  

# My Test Environment
jruby-complete.jar Version: 1.7.15  
local jruby version: 1.5.6  
OS: Debian Jessie  
