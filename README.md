# TANTO
                 Overview of the Tool

This tool is developed in C++ and includes features that are often utilized in security research or penetration testing. However, it’s important to note that using such tools can be legally and ethically sensitive, and they should only be employed in controlled environments, such as during authorized security assessments or research.

### Key Features

  1.  User Authentication 
   -  User and Password Entry : The requirement for user credentials serves a dual purpose: it adds a layer of security to prevent unauthorized access and acts as a method to evade detection by security solutions. This feature can help ensure that only authorized individuals can run the tool, even if it is found on a system.

  2.  Mouse Movement for Sandbox Bypassing 
   -  Mouse Movement : The tool requires users to move the mouse quickly after entering their credentials. This action can potentially help in bypassing sandbox environments that are commonly used by antivirus solutions and EDRs (Endpoint Detection and Response systems) to detect automated or suspicious behavior. Many security solutions analyze processes for signs of non-human interaction, and simulating real user activity can help avoid triggering alerts.

  3.  Debugger Detection 
   -  IsDebuggerPresent Function : The tool employs the `IsDebuggerPresent` function to check if it is being run within a debugger. Debuggers are often used by security researchers and analysts to inspect the behavior of applications. By detecting the presence of a debugger, the tool can alter its behavior to avoid detection or to prevent analysis.

### Features Breakdown

[1] Dump Process
   - This feature allows the tool to capture the memory of any running process on the system. This is typically done using privileged access rights and can be useful for forensic analysis, malware analysis, or recovering information from crashed applications.

  [2]  Dump SAM and SYSTEM Hives 
   - This feature enables the tool to extract and backup the Security Account Manager (SAM) and SYSTEM hives from the Windows registry. These hives contain critical security information, including user accounts and their hashed passwords. This capability is particularly powerful and should be used with caution and only in authorized scenarios.

  [3]  Service Management 
   - The tool provides functionality to stop or manage system services. This can be useful for stopping services that may interfere with the tool's operation or for testing the resilience of services against unauthorized modifications.

  [4]  List Processes 
   - The capability to list all running processes on a system is fundamental for any security tool. It allows users to monitor the system's state and identify any suspicious processes that may need further investigation.

  [5]  Process Management 
   - This feature allows for the termination of specific processes. It provides users with the ability to clean up the system by stopping unwanted or malicious processes that may be running.
