# Ocasta
This project consists of the tools to replay traces on Linux system calls, Windows API calls and gconf API calls, a versioning key-value database, utilities for versioning files, and the monitor to collect traces on Linux and Windows.

The monitor for Linux system calls, kernel_logger, is implemented as a kernel module that modifies the system call table in Linux kernel to intercept system calls. It not only collects miscellaneous information on system calls such as timestamps, process id, and the type of system calls, but also can be configured to collect the actual data passed to system calls such as data being written to files, which can be used to implement or reconstruct a versioing file system.

On the contrary, the monitor for Windows API calls, TraceAPI, is implemented as a user application that uses process injection to modify the Import Address Table (IAT) of all running applications to intercept Windows API calls such as those access and update Windows registry. Different from kernel_logger, TraceAPI logs the information on Windows API calls in text format.

Similarly the monitor for gconf API calls is also implemented as a user application that uses dynamic shared library overloading to intercept gconf API calls made from all running applications.

This set of tools was designed to run reliably and efficiently. They were successfully used to collect information on Linux system calls, particularly those access and update files, and Windows API calls, particularly those access and update Windows registry, on 24 Debian desktops and 5 Windows desktops in computer labs and homes from over 100 users for as long as two months. The information collected was used for the publication of "Ocasta: Clustering Configuration Settings for Error Recovery" in the proceedings of the 44th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN2014).
