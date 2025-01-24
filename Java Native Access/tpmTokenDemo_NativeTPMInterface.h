//
// Created by jagu on 24/01/2025.
//

#ifndef TPMTOKENDEMO_NATIVETPMINTERFACE_H
#define TPMTOKENDEMO_NATIVETPMINTERFACE_H

#pragma once

#ifdef _WIN32
  #ifdef BUILDING_TPM_API
    #define TPM_API __declspec(dllexport)
  #else
    #define TPM_API __declspec(dllimport)
  #endif
#else
  #define TPM_API
#endif

#endif //TPMTOKENDEMO_NATIVETPMINTERFACE_H
