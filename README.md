# Kernel Level Reference Monitor for File Protection 

## Linux Kernel Module (LKM) Specification

This specification is related to a Linux Kernel Module (LKM) implementing a reference monitor for file protection. The reference monitor can be in one of the following four states:

- OFF, meaning that its operations are currently disabled;
- ON, meaning that its operations are currently enabled;
- REC-ON/REC-OFF, meaning that it can be currently reconfigured (in either ON or OFF mode).

The configuration of the reference monitor is based on a set of file system paths. Each path corresponds to a file/dir that cannot be currently opened in write mode. 
Hence, any attempt to write-open the path needs to return an error, independently of the user-id that attempts the open operation.

Reconfiguring the reference monitor means that some path to be protected can be added/removed. 
In any case, changing the current state of the reference monitor requires that the thread that is running this operation needs to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password that is reference-monitor specific. 
This means that the encrypted version of the password is maintained at the level of the reference monitor architecture for performing the required checks.

It is up to the software designer to determine if the above states ON/OFF/REC-ON/REC-OFF can be changed via VFS API or via specific system-calls. 
The same is true for the services that implement each reconfiguration step (addition/deletion of paths to be checked). 
Together with kernel level stuff, the project should also deliver user space code/commands for invoking the system level API with correct parameters.

In addition to the above specifics, the project should also include the realization of a file system where a single append-only file should record the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:

- the process TGID
- the thread ID
- the user-id
- the effective user-id
- the program path-name that is currently attempting the open
- a cryptographic hash of the program file content

The computation of the cryptographic hash and the writing of the above tuple should be carried in deferred work.

### Installation
1. Clone the repo
   ```sh
   git clone https://github.com/Zudel/ReferenceMonitor.git
   ```
2.  Build and install the module through the main Makefile contained in `ReferenceMonitor` directory passing the password as a parameter, with the following command:
   ```sh
   make PW=<password>
   ```

### USAGE
The following commands are available to manage the reference monitor:

* Switch the state of the reference monitor
 ```sh
  make switch_state
  ```
  
  * add a path to the blacklist
 ```sh
  make add_path_blacklist path=<path>
  ```

* Remove a path from the blacklist
```sh
  make rm_path_blacklist path=<path>
  ```

* Print all paths of the blacklist
```sh
  make print_blacklist
  ```

* Write a text string to a file where text and path is passed by parameters
```sh
  make write_test path=<path> text=<text>
  ```

* Create a directory with pathname passed by parameter
```sh
  make mkdir_test path=<pathname>
  ```

* Create device node or (special) file
```sh
  make mknod_test 
  ```

* Setting file attributes 
```sh
  make setattr_test path=<path>
  ```

* Rename a file or directory. 
```sh 
  make rename_test old_path=<old_path> new_path=<new_path>
  ```

* Create symlink
```sh
  make symblink_test path=<pathname> sym_path=<sym path>
  ```

* remove a hard link to a file
```sh
  make unlink_test path=<path>
  ```

* Create hard link to a file
```sh
  make link_test path=<path> hl_path=<hard link path> 
  ```

*  Create a regular file
```sh
  make create_test path=<path>
  ```





