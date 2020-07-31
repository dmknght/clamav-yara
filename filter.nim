# Requires nim. `sudo apt install nim`
# `nim c filter.nim` to compile or `nim c -r .nim` to compile and run
import os
import strutils

const
  # folder = "/tmp/clamav-yara/rules/" # EDIT here
  folder = "rules/"

var
  unixRules = "import \"elf\"\nimport \"hash\"\n"
  phpRules = "import \"elf\"\nimport \"hash\"\n"
  emailRules = "import \"elf\"\nimport \"hash\"\n"
  htmlRules = "import \"elf\"\nimport \"hash\"\n"
  javaRules = "import \"elf\"\nimport \"hash\"\n"
  jsRules = "import \"elf\"\nimport \"hash\"\n"
  multiOSRules = "import \"elf\"\nimport \"hash\"\n"
  

if not dirExists("ParrotRules"):
  createDir("ParrotRules")

for kind, path in walkDir(folder):
  echo "Checking " & path
  var
      ruleText = ""
      ruleName = ""

  for line in lines(path):
    ruleText &= line & "\n"
    if line.startsWith("rule "):
      ruleName = line.split(" ")[1]
    elif line.startsWith("}"):
      if ruleName.startsWith("Unix") and not contains(unixRules, ruleName):
        unixRules &= "\n" & ruletext
      elif ruleName.startsWith("Php") and not contains(phpRules, ruleName):
        phpRules &= "\n" & ruletext
      elif ruleName.startsWith("Email") and not contains(emailRules, ruleName):
        emailRules &= "\n" & ruletext
      elif ruleName.startsWith("Html") and not contains(htmlRules, ruleName):
        htmlRules &= "\n" & ruletext
      elif ruleName.startsWith("Java") and not contains(javaRules, ruleName):
        javaRules &= "\n" & ruletext
      elif ruleName.startsWith("Js") and not contains(jsRules, ruleName):
        jsRules &= "\n" & ruletext
      elif ruleName.startsWith("Multios") and not contains(multiOSRules, ruleName):
        multiOSRules &= "\n" & ruletext
      ruleText = ""
      ruleName = ""

writeFile("ParrotRules/unix.yara", unixRules)
writeFile("ParrotRules/php.yara", phpRules)
writeFile("ParrotRules/email.yara", emailRules)
writeFile("ParrotRules/html.yara", htmlRules)
writeFile("ParrotRules/java.yara", javaRules)
writeFile("ParrotRules/js.yara", jsRules)
writeFile("ParrotRules/multios.yara", multiOSRules)