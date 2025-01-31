# Tpm Demo App

![Maven Build](https://github.com/jgteam/tpmTokenDemo/actions/workflows/maven.yml/badge.svg)

! README.md is currently under construction !

[Setup and Demo Video](https://youtu.be/7O_CmKDt6ic)

[Preparation TPM_API.dll Video](https://youtu.be/gQwY6oNcEzE)

[Preparation tpm2-tss Video](https://youtu.be/hU681bsMSA0)

## Repo Structure

```
.
├── Java Native Access [! all files for the TPM_API.dll]
│   ├── cmake-build-debug
│   │   └── TPM_API.dll [! bundled and prebuild TPM_API.dll]
│   ├── compiled-libs [! bundled and prebuild dependencies]
│   │   ├── tss2-esys.dll
│   │   ├── tss2-mu.dll
│   │   ├── tss2-rc.dll
│   │   ├── tss2-sys.dll
│   │   ├── tss2-tcti-mssim.dll
│   │   ├── tss2-tcti-tbs.dll
│   │   ├── tss2-tctildr.dll
│   │   └── ...
│   ├── tpm2-tss-master [! bundled dependency]
│   │   └── ...
│   ├── CMakeLists.txt
│   ├── tpmTokenDemo_NativeTPMInterface.cpp
│   └── tpmTokenDemo_NativeTPMInterface.h
├── library [! bundled and prebuild dependencies]
│   ├── libgcc_s_seh-1.dll
│   ├── libssp-0.dll
│   ├── libstdc++-6.dll
│   ├── libwinpthread-1.dll
│   ├── tss2-esys.dll
│   ├── tss2-mu.dll
│   ├── tss2-rc.dll
│   ├── tss2-sys.dll
│   ├── tss2-tcti-mssim.dll
│   ├── tss2-tcti-tbs.dll
│   └── tss2-tctildr.dll
├── src [Java project source]
│   └── main
│       └── java
│           ├── logger
│           │   └── Logger.java
│           └── tpmTokenDemo
│               ├── App.java
│               ├── AppLogic.java
│               ├── AppShell.java
│               ├── ConfigDialog.java
│               ├── LogDialog.java
│               ├── NativeTPMInterface.java
│               └── TokenViewerDialog.java
├── README.md
└── pom.xml [maven]
```

## Needed Ressoures:
- [tpm2-tss](https://github.com/tpm2-software/tpm2-tss)
- [TPM Simulator](https://www.microsoft.com/en-us/download/details.aspx?id=52507)

### Notes for Future README:
- java.library.path 

Deps:
- [libgcc_s_seh-1.dll](library/libgcc_s_seh-1.dll)
- [libstdc++-6.dll](library/libstdc%2B%2B-6.dll)
- [libwinpthread-1.dll](library/libwinpthread-1.dll)
- [libssp-0.dll](library/libssp-0.dll)
-> can be found in MinGW

This Repo countains already build DLLs and dependencies... it is always better to build them yourself on your machine for your device!
