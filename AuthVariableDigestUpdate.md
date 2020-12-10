# Title: Digest Algorithm flexibility in Authenticated Variable signatures

# Status: Draft

# Document: UEFI Specification Version 2.8

# License

SPDX-License-Identifier: CC-BY-4.0

# Submitter: [TianoCore Community](https://www.tianocore.org)

# Summary of the change
EFI_VARIABLE_AUTHENTICATION_2 specifies the SignedData.digestAlgorithms to be always
SHA256. The implication is that the signing algorithm can use RSA keys greater than
2048 bits, but the digest algorithm remains SHA256. The proposed change is to allow
digest algorithm to be greater than SHA256.

# Benefits of the change
This brings agility to the signing mechanism of Authenticated variables by allowing
it to sign a larger digest.

# Impact of the change
There is no impact on the existing Authenticated variables.

# Detailed description of the change [normative updates]

<b>Bold text</b> indicates the proposed change

8.2.2 Using the EFI_VARIABLE_AUTHENTICATION_2 descriptor
When the attribute EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is set, then the Data buffer shall begin with an instance of a complete (and serialized) ...

Construct a DER-encoded PKCS #7 version 1.5 SignedData (see [RFC2315]) with the signed content as follows:

a. SignedData.version shall be set to 1

b. SignedData.digestAlgorithms shall contain the digest algorithm used when preparing the signature. <b>Only a digest algorithm greater than or equal to SHA-256 is accepted.</b>


# Special Instructions
NA
