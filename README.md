# TANTO
                 Overview of the Tool

The tool is developed in C++ and includes features that are often used in security research or penetration testing. However, it is important to note that the use of such tools can be legally and ethically sensitive and they should only be used in controlled environments, such as security assessments or authorized research and testing of security mechanisms.

![Capture](https://github.com/user-attachments/assets/6dfaca08-feec-446a-ab45-ace2a8c0b405)


#Key Features

User Authentication to Bypass Sandbox
User Login and Password: Requiring user credentials serves a dual purpose: it adds a layer of security to prevent unauthorized access and acts as a way to evade detection by security solutions. This feature can help ensure that only authorized individuals can run the tool, even if it is found on a system. It is intended to bypass EDR/AV sandboxes if the password is not provided or if the password is entered incorrectly. This is to bypass EDR/AV sandboxes as they do not have the ability to bypass authentication.

Mouse Movement to Bypass Sandbox
Mouse Movement: This tool requires users to move the mouse quickly after entering their credentials. This can potentially help bypass sandbox environments that are commonly used by antivirus solutions and EDRs (Endpoint Detection and Response Systems) to detect automated or suspicious behavior. Many security solutions analyze processes for signs of non-human interaction, and simulating real user activity can help prevent alerts from being raised. (EDR/AV may disable the tool based on suspicious and malicious behavior.)

Debugger Detection
IsDebuggerPresent Function: This tool uses the IsDebuggerPresent function to check whether it is running in a debugger. Debugging is often used by security researchers and analysts to examine the behavior of applications. By detecting the presence of a debugger, the tool can change its behavior to avoid detection or to avoid analysis.

[1] Process Dumping
This feature allows the tool to capture the memory of any process running on the system. This is usually done using privileged access rights and can be used for forensic analysis, malware analysis or data recovery from crashed applications. In addition, it can dump lsass or processes that have elevated access levels.

[2] Dump SAM and SYSTEM hives

This feature enables the tool to extract and backup the Security Account Management (SAM) and SYSTEM hives from the Windows registry. These hives contain important security information, including user accounts and their hashed passwords. This feature is particularly powerful and should be used with caution and only in authorized scenarios. To avoid this, use the Backup privilege.

[3] Service Management

This tool provides functionality to stop or manage system services. This tool has the ability to stop, run, and terminate Windows services. To stop sensitive services, we need a higher level of privilege.

This project can help you stop important and security services.

https://github.com/lab52io/StopDefender

[4] Process List

Provides the ability to list all running processes on a system. It displays processes that are running normally and processes that are running with elevated privileges.

[5] Process Management

This feature only stops processes in normal or elevated privileges. This can be useful for terminating a malicious process or for testing how the operating system reacts if an important process is stopped or terminated.
