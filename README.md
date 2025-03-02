# Tpm Demo App

![Maven Build](https://github.com/jgteam/tpmTokenDemo/actions/workflows/maven.yml/badge.svg)

For the full setup and walkthrough, please watch the following video:

[Setup and Demo Video](https://youtu.be/7O_CmKDt6ic)

For additional information on the preparation of the TPM_API.dll and tpm2-tss, please watch the following videos:

[Preparation TPM_API.dll Video](https://youtu.be/gQwY6oNcEzE)

[Preparation tpm2-tss Video](https://youtu.be/hU681bsMSA0)

This is a demo app to show how to use the TPM capabilities on the windows platforms and will be a Proof of Concept for storing sensitive OpenID Connect tokens securely when used with native desktop applications.

This Demo is part of a Bachelor's thesis project by Jannis Günsche from the University of Applied Sciences in Darmstadt, Germany.

## Disclaimer

Disclaimer: This app is not intended for production use and is only a proof of concept. It shows the secure storage of sensitive data in a native desktop application but does not handle all edge cases and errors that might occur in a real-world application. It also does not handle the token inside the app in a secure way, as this demo is only a proof of concept.

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

## Content

The Demo consists of one part:
  1. A GUI-App written in Java which is build for Windows.

The GUI-App is used to show how the data can be stored and retrieved securely.

## Prerequisites

To run the Java Demo App, you need to have all the .DLLs that are in the `library`-folder accessible through the `java.library.path`-variable. You also need the TPM_API.dll that is located in the `Java Native Access/cmake-build-debug`-folder accessible through the `java.library.path`-variable.

All needed dependencies are already bundled in the repository.

### Getting the dependencies yourself

Following dependencies can be found in the MinGW (needs to be installed on the system of the user) installation folder:

- libgcc_s_seh-1.dll
- libssp-0.dll
- libstdc++-6.dll
- libwinpthread-1.dll

The following dependencies can be build with the tpm2-tss project (how to build is shown in the video linked above):

- tss2-esys.dll
- tss2-mu.dll
- tss2-rc.dll
- tss2-sys.dll
- tss2-tcti-mssim.dll
- tss2-tcti-tbs.dll
- tss2-tctildr.dll

The TPM_API.dll can be build with the TPM_API project (located in the `Java Native Access`-folder) (how to build is shown in the video linked above, needs tpm2-tss to build):

- TPM_API.dll

## Getting Started

This project is build with Maven.

The GUI-App is automatically build by GitHub Actions and the artifacts are available for download in the 'Actions' tab of this repository. To be able to download the artifacts, you need to be logged in to GitHub.

To build the Artifacts yourself, you can use the following commands after cloning the repository:

```shell
maven clean install
```

The jar file will be located in the target folder (E. g. `target/tpmTokenDemo-1.0.jar`).

To run the jar file, you can use the following command:

```shell
java -jar tpmTokenDemo-1.0.jar
```

## Usage of the TPM Simulator

To use the TPM Simulator, you need to download the TPM Simulator from the following link: [TPM Simulator Download](https://www.microsoft.com/en-us/download/details.aspx?id=52507)

When you have downloaded the TPM Simulator, you can start the TPM Simulator by opening the executable. The TPM Simulator will start, and you can use the simulator now with the TPM Demo App. The Demo App is set up with the default settings for the TPM Simulator.

## Measuring time

To measure the time you can press the separate measure-button in the App. This will measure retrieving the token 100 times and log the time simultaneously. The time is measured in milliseconds and can be seen in the time measurement dialog. To open the time measurement dialog, you can press the "View Time Measurements" button in the App.

