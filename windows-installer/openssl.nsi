
######################################################
# NSIS windows installer script file
# Requirements: NSIS 3.0 must be installed with the MUI plugin
# Usage notes:
# This script expects to be executed from the directory it is
# currently stored in.  It expects a 32 bit and 64 bit windows openssl
# build to be present in the ..\_build32 and ..\_build64 directories
# respectively
# ####################################################

!include "MUI.nsh"

# The name of the output file we create when building this
# NOTE version is passed with the /D option on the command line
OutFile "openssl-${VERSION}-installer.exe"

# The name that will appear in the installer title bar
NAME "openssl ${VERSION}"

# This section is run if installation of 32 bit binaries are selected
Section "32 Bit Binaries"
	SetOutPath $INSTDIR\x32
	File ..\_build32\libcrypto-3.dll
	File ..\_build32\libssl-3.dll
	File ..\_build32\apps\openssl.exe
	SetOutPath $INSTDIR\x32\providers
	File ..\_build32\providers\fips.dll
	File ..\_build32\providers\legacy.dll
SectionEnd


# This section is run if installation of the 64 bit binaries are selectd
Section "64 Bit Binaries"
	SetOutPath $INSTDIR\x64
	File ..\_build64\libcrypto-3-x64.dll
	File ..\_build64\libssl-3-x64.dll
	File ..\_build64\apps\\openssl.exe
	SetOutPath $INSTDIR\x64\providers
	File ..\_build64\providers\fips.dll
	File ..\_build64\providers\legacy.dll
SectionEnd

# Give the user the opportunity to include the uninstaller
Section "Uninstaller"
	WriteUninstaller $INSTDIR\uninstall.exe
SectionEnd

# This is run on uninstall
Section "Uninstall"
	RMDIR /r $INSTDIR
SectionEnd

!insertmacro MUI_PAGE_WELCOME

!insertmacro MUI_PAGE_LICENSE ../LICENSE.TXT

!insertmacro MUI_PAGE_COMPONENTS

!define MUI_DIRECTORYPAGE_TEXT_DESTINATION "c:\Program Files\openssl-${VERSION}"
!insertmacro MUI_PAGE_DIRECTORY

!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"
