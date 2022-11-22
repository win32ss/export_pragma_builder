# export_pragma_builder
Builds a file full of Visual C++ export-forward pragma directives for a PE32(+) file wrapper.
It also retrieves the preferred image base of the original PE file and creates a pragma directive to specify the address as the base address of the wrapper;
this is necessary for ensuring functional WOW64 in Windows 7 and earlier.

Usage of the application is as follows:

**With command line parameters:**
---------------------------------
Use the following syntax:
*ng_pragma_builder PEPath PragmaPath PEName*

PEPath: the path of the original PE image (typically a DLL or EXE file compatible with 32 or 64 bit Windows)

PragmaPath: the path and filename for the pragma file to be constructed

PEName: the "original" PE image name to be used for export-forwarding (e.g. kernel33 for a renamed kernel32.dll)

This option is desireable for batch operations.

**Without command line parameters:**
---------------------------------

The application will prompt for each parameter individually.

**Important note**
--------------------------------
Both x86 and x64 builds of the application are available. Usage of the x86 version on an x64 system is not recommended due to 
WOW64 file redirection, which redirects file access from 32 bit applications to 32 bit system directories such as SysWOW64, when
64 bit system directories such as System32 are specified.
