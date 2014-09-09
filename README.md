What the WAF is wrong with you, man?!

#Info
jruby-complete.jar Version: 1.7.15  
local jruby version: 1.5.6  
OS: Debian Jessie (powered by both Debian Testing and Kali-Bleeding-Edge repos)  

#Installation
Download jruby-complete jar file from [JRuby](http://www.jruby.org/download)  
Open the "Burp Suite"  
Go to "Extender"  
Go to "Options"  
On "Ruby Environment" section set the "Location of JRuby JAR file" to   "\[foo\]/\[bar\]/jruby-complete-\[version\].jar"  
Go to "Extensions"  
Click "Add"  
Set "Extension Type" to "Ruby"  
Click "Select File" and choose "\[foo\]/\[bar\]/what-the-waf.rb"  

#Quickref

## Usage
\[TODO\]

## Development
######Compile burp's jruby script
jruby HelloWorld.rb -J" -cp burp"  

######Build jar
rm -r burp  
mkdir burp  
javac -d burp/ burp-src/\*.java  
jruby doc/HelloWorld.rb  
jrubyc doc/HelloWorld.rb  
cp HelloWorld.class burp/  
jar cvf HelloWorld.jar burp/\*.class  
