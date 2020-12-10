/** @file
  Implement UnitTest for the Authenticated Variables.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/UnitTestLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Guid/AuthenticatedVariableFormat.h>
#include <Guid/GlobalVariable.h>

extern UINT8  gPkRsa2048Sha256[];
extern UINT32 gPkRsa2048Sha256Size;
extern UINT8  gPkNewRsa2048Sha256[];
extern UINT32 gPkNewRsa2048Sha256Size;
extern UINT8  gPkRsa3072Sha256[];
extern UINT32 gPkRsa3072Sha256Size;
extern UINT8  gPkNewRsa3072Sha256[];
extern UINT32 gPkNewRsa3072Sha256Size;
extern UINT8  gPkRsa4096Sha256[];
extern UINT32 gPkRsa4096Sha256Size;
extern UINT8  gPkNewRsa4096Sha256[];
extern UINT32 gPkNewRsa4096Sha256Size;
extern UINT8  gPkRsa3072Sha384[];
extern UINT32 gPkRsa3072Sha384Size;
extern UINT8  gPkNewRsa3072Sha384[];
extern UINT32 gPkNewRsa3072Sha384Size;
extern UINT8  gPkRsa4096Sha512[];
extern UINT32 gPkRsa4096Sha512Size;
extern UINT8  gPkNewRsa4096Sha512[];
extern UINT32 gPkNewRsa4096Sha512Size;

#define UNIT_TEST_NAME    "AuthVarTest"
#define UNIT_TEST_VERSION "0.1"
typedef enum {
  CONTEXT_RSA2048_SHA256 = 1,
  CONTEXT_RSA3072_SHA256,
  CONTEXT_RSA4096_SHA256,
  CONTEXT_RSA3072_SHA384,
  CONTEXT_RSA4096_SHA512
} AuthVarTestContext;


STATIC UINT32 mRsa2048Sha256 = CONTEXT_RSA2048_SHA256;
STATIC UINT32 mRsa3072Sha256 = CONTEXT_RSA3072_SHA256;
STATIC UINT32 mRsa4096Sha256 = CONTEXT_RSA4096_SHA256;
STATIC UINT32 mRsa3072Sha384 = CONTEXT_RSA3072_SHA384;
STATIC UINT32 mRsa4096Sha512 = CONTEXT_RSA4096_SHA512;

/**
  Set the platform secure boot mode to "custom" or "standard"
  @param[in]  CustomMode        Value of 1 indicates Custom Mode.
                                Value of 0 indicates Standard Mode.

  @retval     EFI_SUCCESS       The platform has switched to the requested mode successfully
  @retval     other             Failure to set the required boot mode
**/
EFI_STATUS
SetSecureBootMode(
  IN  UINT8     SecureBootMode
  )
{
  return gRT->SetVariable (
              EFI_CUSTOM_MODE_NAME,
              &gEfiCustomModeEnableGuid,
              EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
              sizeof (UINT8),
              &SecureBootMode
              );
}

/**
  Enroll the base Authenticated Variable into the storage
  @param[in]  Context           Context is passed during test case registration.
                                It is an integer value indicating which signed
                                algorithm data to be used for enrollment.

  @retval  UNIT_TEST_PASSED     The test case is a success
  @retval  other                Unit Test Framework value from the respective assert
**/
UNIT_TEST_STATUS
EFIAPI
AuthVarEnroll (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS  Status;
  UINT32      Attr;
  UINT32      Value;
  UINTN       DataSize;
  VOID        *Data;

  Value = *(UINT32 *)Context;

  switch (Value) {
    case CONTEXT_RSA2048_SHA256:
      DataSize = gPkRsa2048Sha256Size;
      Data     = gPkRsa2048Sha256;
      break;

    case CONTEXT_RSA3072_SHA256:
      DataSize = gPkRsa3072Sha256Size;
      Data     = gPkRsa3072Sha256;
      break;

    case CONTEXT_RSA4096_SHA256:
      DataSize = gPkRsa4096Sha256Size;
      Data     = gPkRsa4096Sha256;
      break;

    case CONTEXT_RSA3072_SHA384:
      DataSize = gPkRsa3072Sha384Size;
      Data     = gPkRsa3072Sha384;
      break;

    case CONTEXT_RSA4096_SHA512:
      DataSize = gPkRsa4096Sha512Size;
      Data     = gPkRsa4096Sha512;
      break;

    default:
      UT_ASSERT_TRUE (0);
  }

  //
  // Set the platform mode in custom mode to enroll the
  // base variable into the Authenticated Variable storage.
  //
  Status = SetSecureBootMode (CUSTOM_SECURE_BOOT_MODE);
  UT_ASSERT_TRUE (Status == EFI_SUCCESS);

  //
  // Enroll the variable to be used for sign verification
  // for next updates.
  //
  Attr = EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_RUNTIME_ACCESS |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

  Status = gRT->SetVariable (
                EFI_PLATFORM_KEY_NAME,
                &gEfiGlobalVariableGuid,
                Attr,
                DataSize,
                Data
                );
  UT_ASSERT_TRUE (Status == EFI_SUCCESS);

  //
  // Clear the custom mode of platform
  //
  Status = SetSecureBootMode (STANDARD_SECURE_BOOT_MODE);
  UT_ASSERT_TRUE (Status == EFI_SUCCESS);

  return UNIT_TEST_PASSED;
}

/**
  Update the Authenticated Variable enrolled earlier in custom mode
  @param[in]  Context           Context is passed during test case registration.
                                It is an integer value indicating which signed
                                algorithm data to be used for update.

  @retval  UNIT_TEST_PASSED     The test case is a success
  @retval  other                Unit Test Framework value from the respective assert
**/
UNIT_TEST_STATUS
EFIAPI
AuthVarUpdate (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS Status;
  UINT32     Attr;
  UINT32      Value;
  UINTN       DataSize;
  VOID        *Data;

  Value = *(UINT32 *) Context;

  switch (Value) {
    case CONTEXT_RSA2048_SHA256:
      DataSize = gPkNewRsa2048Sha256Size;
      Data     = gPkNewRsa2048Sha256;
      break;

    case CONTEXT_RSA3072_SHA256:
      DataSize = gPkNewRsa3072Sha256Size;
      Data     = gPkNewRsa3072Sha256;
      break;

    case CONTEXT_RSA4096_SHA256:
      DataSize = gPkNewRsa4096Sha256Size;
      Data     = gPkNewRsa4096Sha256;
      break;

    case CONTEXT_RSA3072_SHA384:
      DataSize = gPkNewRsa3072Sha384Size;
      Data     = gPkNewRsa3072Sha384;
      break;

    case CONTEXT_RSA4096_SHA512:
      DataSize = gPkNewRsa4096Sha512Size;
      Data     = gPkNewRsa4096Sha512;
      break;

    default:
      UT_ASSERT_TRUE (0);
  }

  Attr = EFI_VARIABLE_NON_VOLATILE |
         EFI_VARIABLE_RUNTIME_ACCESS |
         EFI_VARIABLE_BOOTSERVICE_ACCESS |
         EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

  //
  // Update the Authenticated Variable enrolled earlier in custom mode
  //
  Status = gRT->SetVariable (
                EFI_PLATFORM_KEY_NAME,
                &gEfiGlobalVariableGuid,
                Attr,
                DataSize,
                Data
                );
  UT_ASSERT_TRUE (Status == EFI_SUCCESS);
  return UNIT_TEST_PASSED;
}

/**
  Register the test cases for RSA2048/SHA256 signing algorithm
  @param[in]  TestSuite         Test Suite created to manage RSA2048/SHA256 test cases

  @retval  UNIT_TEST_PASSED     The test case registration is successful
  @retval  other                Unit Test Framework value from the respective assert
**/
EFI_STATUS
EFIAPI
AuthVarRegisterRsa2048Sha256Tests (
  IN UNIT_TEST_SUITE_HANDLE  TestSuite
  )
{
  EFI_STATUS Status;
  Status  = AddTestCase (TestSuite, "RSA2048/SHA256 Auth Var Enroll", "RSA2048.SHA256.Enroll", AuthVarEnroll, NULL, NULL, &mRsa2048Sha256);
  Status |= AddTestCase (TestSuite, "RSA2048/SHA256 Auth Var Update", "RSA2048.SHA256.Update", AuthVarUpdate, NULL, NULL, &mRsa2048Sha256);
  return Status;
}

/**
  Register the test cases for RSA3072/SHA256 signing algorithm
  @param[in]  TestSuite         Test Suite created to manage RSA3072/SHA256 test cases

  @retval  UNIT_TEST_PASSED     The test case registration is successful
  @retval  other                Unit Test Framework value from the respective assert
**/
EFI_STATUS
EFIAPI
AuthVarRegisterRsa3072Sha256Tests (
  IN UNIT_TEST_SUITE_HANDLE  TestSuite
  )
{
  EFI_STATUS Status;
  Status  = AddTestCase (TestSuite, "RSA3072/SHA256 Auth Var Enroll", "RSA3072.SHA256.Enroll", AuthVarEnroll, NULL, NULL, &mRsa3072Sha256);
  Status |= AddTestCase (TestSuite, "RSA3072/SHA256 Auth Var Update", "RSA3072.SHA256.Update", AuthVarUpdate, NULL, NULL, &mRsa3072Sha256);
  return Status;
}

/**
  Register the test cases for RSA4096/SHA256 signing algorithm
  @param[in]  TestSuite         Test Suite created to manage RSA4096/SHA256 test cases

  @retval  UNIT_TEST_PASSED     The test case registration is successful
  @retval  other                Unit Test Framework value from the respective assert
**/
EFI_STATUS
EFIAPI
AuthVarRegisterRsa4096Sha256Tests (
  IN UNIT_TEST_SUITE_HANDLE  TestSuite
  )
{
  EFI_STATUS Status;
  Status  = AddTestCase (TestSuite, "RSA4096/SHA256 Auth Var Enroll", "RSA4096.SHA256.Enroll", AuthVarEnroll, NULL, NULL, &mRsa4096Sha256);
  Status |= AddTestCase (TestSuite, "RSA4096/SHA256 Auth Var Update", "RSA4096.SHA256.Update", AuthVarUpdate, NULL, NULL, &mRsa4096Sha256);
  return Status;
}

/**
  Register the test cases for RSA3072/SHA384 signing algorithm
  @param[in]  TestSuite         Test Suite created to manage RSA3072/SHA384 test cases

  @retval  UNIT_TEST_PASSED     The test case registration is successful
  @retval  other                Unit Test Framework value from the respective assert
**/
EFI_STATUS
EFIAPI
AuthVarRegisterRsa3072Sha384Tests (
  IN UNIT_TEST_SUITE_HANDLE  TestSuite
  )
{
  EFI_STATUS Status;
  Status  = AddTestCase(TestSuite, "RSA3072/SHA384 Auth Var Enroll", "RSA3072.SHA384.Enroll", AuthVarEnroll, NULL, NULL, &mRsa3072Sha384);
  Status |= AddTestCase(TestSuite, "RSA3072/SHA384 Auth Var Update", "RSA3072.SHA384.Update", AuthVarUpdate, NULL, NULL, &mRsa3072Sha384);
  return Status;
}

/**
  Register the test cases for RSA4096/SHA512 signing algorithm
  @param[in]  TestSuite         Test Suite created to manage RSA4096/SHA512 test cases

  @retval  UNIT_TEST_PASSED     The test case registration is successful
  @retval  other                Unit Test Framework value from the respective assert
**/
EFI_STATUS
EFIAPI
AuthVarRegisterRsa4096Sha512Tests (
  IN UNIT_TEST_SUITE_HANDLE  TestSuite
  )
{
  EFI_STATUS Status;
  Status  = AddTestCase (TestSuite, "RSA4096/SHA512 Auth Var Enroll", "RSA4096.SHA512.Enroll", AuthVarEnroll, NULL, NULL, &mRsa4096Sha512);
  Status |= AddTestCase (TestSuite, "RSA4096/SHA512 Auth Var Update", "RSA4096.SHA512.Update", AuthVarUpdate, NULL, NULL, &mRsa4096Sha512);
  return Status;
}

/**
  Register Authenticated Variable tests based on different signing schemes.
  The following test suites are registered
  o RSA2048/SHA256
  o RSA3072/SHA256
  o RSA4096/SHA256
  o RSA3072/SHA384
  o RSA4096/SHA512

  @retval  EFI_SUCCESS           All test suites are registered
  @retval  EFI_OUT_OF_RESOURCES  System is out of resources for registering test suite
**/
EFI_STATUS
EFIAPI
AuthVarRegisterTests (
 UNIT_TEST_FRAMEWORK_HANDLE Framework
 )
{
  EFI_STATUS              Status;
  UNIT_TEST_SUITE_HANDLE  Rsa2048Sha256Suite;
  UNIT_TEST_SUITE_HANDLE  Rsa3072Sha256Suite;
  UNIT_TEST_SUITE_HANDLE  Rsa4096Sha256Suite;
  UNIT_TEST_SUITE_HANDLE  Rsa3072Sha384Suite;
  UNIT_TEST_SUITE_HANDLE  Rsa4096Sha512Suite;

  //
  // Create Test Suite for Authenticated Variables signed with RSA2048/SHA256
  //
  Status = CreateUnitTestSuite (&Rsa2048Sha256Suite, Framework, "AuthVar RSA2048/SHA256", "RSA2048.SHA256", NULL, NULL);
  if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to create Authenticated Variable RSA2048/SHA256 Test Suite (0x%x)", Status));
      goto EXIT;
  }

  //
  // Register Test cases for RSA2048/SHA256
  //
  Status = AuthVarRegisterRsa2048Sha256Tests(Rsa2048Sha256Suite);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to register test cases for RSA2048/SHA256 suite (0x%x)", Status));
    goto EXIT;
  }

  //
  // Create Test Suite for Authenticated Variables signed with RSA3072/SHA256
  //
  Status = CreateUnitTestSuite (&Rsa3072Sha256Suite, Framework, "AuthVar RSA3072/SHA256", "RSA3072.SHA256", NULL, NULL);
  if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to create Authenticated Variable RSA3072/SHA256 Test Suite (0x%x)", Status));
      goto EXIT;
  }

  //
  // Register Test cases for RSA3072/SHA256
  //
  Status = AuthVarRegisterRsa3072Sha256Tests(Rsa3072Sha256Suite);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to register test cases for RSA3072/SHA256 suite (0x%x)", Status));
    goto EXIT;
  }

  //
  // Create Test Suite for Authenticated Variables signed with RSA4096/SHA256
  //
  Status = CreateUnitTestSuite (&Rsa4096Sha256Suite, Framework, "AuthVar RSA4096/SHA256", "RSA4096.SHA256", NULL, NULL);
  if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to create Authenticated Variable RSA4096/SHA256 Test Suite (0x%x)", Status));
      goto EXIT;
  }

  //
  // Register Test cases for RSA4096/SHA256
  //
  Status = AuthVarRegisterRsa4096Sha256Tests(Rsa4096Sha256Suite);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to register test cases for RSA4096/SHA256 suite (0x%x)", Status));
    goto EXIT;
  }

  //
  // Create Test Suite for Authenticated Variables signed with RSA3072/SHA384
  //
  Status = CreateUnitTestSuite (&Rsa3072Sha384Suite, Framework, "AuthVar RSA3072/SHA384", "RSA3072.SHA384", NULL, NULL);
  if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to create Authenticated Variable RSA3072/SHA384 Test Suite (0x%x)", Status));
      goto EXIT;
  }

  //
  // Register Test cases for RSA3072/SHA384
  //
  Status = AuthVarRegisterRsa3072Sha384Tests(Rsa3072Sha384Suite);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to register test cases for RSA3072/SHA384 suite (0x%x)", Status));
    goto EXIT;
  }

  //
  // Create Test Suite for Authenticated Variables signed with RSA4096/SHA512
  //
  Status = CreateUnitTestSuite (&Rsa4096Sha512Suite, Framework, "AuthVar RSA4096/SHA512", "RSA4096.SHA512", NULL, NULL);
  if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to create Authenticated Variable RSA4096/SHA512 Test Suite (0x%x)", Status));
      goto EXIT;
  }

  //
  // Register Test cases for RSA4096/SHA512
  //
  Status = AuthVarRegisterRsa4096Sha512Tests (Rsa4096Sha512Suite);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to register test cases for RSA4096/SHA512 suite (0x%x)", Status));
    goto EXIT;
  }

EXIT:
  if (EFI_ERROR (Status)) {
    Status = EFI_OUT_OF_RESOURCES;
  }
  return Status;
}

/**
  Authenticated Variable Unit Test entry point
**/
EFI_STATUS
EFIAPI
AuthVarUnitTestEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status;
  UNIT_TEST_FRAMEWORK_HANDLE Framework;

  Framework = NULL;

  //
  // Create a Framework object for Authenticated Variable Test
  //
  Status = InitUnitTestFramework (&Framework, UNIT_TEST_NAME, gEfiCallerBaseName, UNIT_TEST_VERSION);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to create Framework Object (Status: %r)\n", Status));
    goto EXIT;
  }

  //
  // Register all the test suites the Unit Test Framwork
  //
  Status = AuthVarRegisterTests (Framework);
  if (EFI_ERROR (Status )) {
      DEBUG ((DEBUG_ERROR, "Failed to register the test suites with the framework (Status: %r)\n", Status));
      goto EXIT;
  }

  //
  // Execute all the tests
  //
  Status = RunAllTestSuites (Framework);

EXIT:
  if (Framework) {
    FreeUnitTestFramework (Framework);
  }
  return Status;
}
