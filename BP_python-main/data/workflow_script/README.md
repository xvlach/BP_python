# script_trigger
This is modified version of application workflow external scripts for Nextcloud server.

Link to original version: https://github.com/nextcloud/workflow_script

This modfication contains added argument to get fully qualified filepath for files.
This will work even with enabled encryption and that was reason to add this commands. 

ADDED 2 new commands:

%p - will give full system file path

%m - will give full name

Example 

cp %p /home/%m

