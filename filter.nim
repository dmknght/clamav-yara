# Requires nim. `sudo apt install nim`
# `nim c filter.nim` to compile or `nim c -r .nim` to compile and run
import os
import strutils

const
  # folder = "/tmp/clamav-yara/rules/" # EDIT here
  folder = "rules/"

var
  unixRules = ""
  phpRules = ""
  emailRules = ""
  htmlRules = ""
  javaRules = ""
  jsRules = ""
  multiOSRules = ""
  

if not dirExists("ParrotRules"):
  createDir("ParrotRules")

for kind, path in walkDir(folder):
  echo "Checking " & path
  var
      ruleText = ""
      platform = ""

  for line in lines(path):
    ruleText &= line & "\n"
    if line.startsWith("rule "):
      platform = line.split(" ")[1]
    elif line.startsWith("}"):
      if platform.startsWith("Unix"):
        unixRules &= "\n" & ruletext
      elif platform.startsWith("Php"):
        phpRules &= "\n" & ruletext
      elif platform.startsWith("Email"):
        phpRules &= "\n" & ruletext
      elif platform.startsWith("Html"):
        phpRules &= "\n" & ruletext
      elif platform.startsWith("Java"):
        phpRules &= "\n" & ruletext
      elif platform.startsWith("Js"):
        phpRules &= "\n" & ruletext
      elif platform.startsWith("Multios"):
        phpRules &= "\n" & ruletext
      ruleText = ""
      platform = ""

writeFile("ParrotRules/unix.yara", unixRules)
writeFile("ParrotRules/php.yara", phpRules)
writeFile("ParrotRules/email.yara", emailRules)
writeFile("ParrotRules/html.yara", htmlRules)
writeFile("ParrotRules/java.yara", javaRules)
writeFile("ParrotRules/js.yara", jsRules)
writeFile("ParrotRules/multios.yara", multiOSRules)