The OSGPKITool scripts are developed in python and are intended to work in the python module 2.4 and higher(especially 2.4 and 2.6). The external packages required for the scripts include:
1) M2Crypto

The following are the common files used and the purpose they serve:

1) OSGPKIClients.ini: This file is a common variable storage file in the form of urls. The file is imported into scripts using ConfigParser and then the urls contained in the file are used of various operations. The contents of the file are static and are not supposed to be changed for a fairly large amount of time.

2) OSGPKIUtils.py: This file is a common utility file that contains functions for key pair generation and certificate signing request generation. It uses the M2Crypto module to perform the said functions and stores the key pair into the specified file as well. The functions in this file are imported for certificate request scripts i.e osg-cert-request and osg-gridadmin-cert-request.

The following is the brief description of each of these scripts and a walk through for the code in them:

1) osg-cert-request: This script as the name suggests is used to request a certificate. It uses the common utility i.e. OSGPKIUtils.py described above to generate and store a key pair on the file system. The certificate signing request is generated form the OSGPKIUtils.py and then sent to the OIM.
The arguments are parsed using the optparse utility since it is compatible with python 2.4. Optparse doesn't handle the required options, hence the handling of the required options are done explicitly.
The key is written in pem format and the csr is base 64 encoded pkcs10 format encrypted using 2048 bits RSA encryption using sha1 digest.

2) osg-cer-retrieve: This script is used to retrieve the requested csr using the request ID. The script checks for the request to be in approved state. If not the script fails asking the user to get it approved first. If in approved state, the script issues the certificate if not issued and then retrieve it in pem format.
After retrieval, the certificate dump is cleansed and formatted as per what is the pem format using several string operations.

3) os-gridadmin-cer-request: This script is used by the gridadmin to request and retrieve certificates(single or in bulk of 50). The script again uses the common script OSGPKIUtils.py to generate the key pair and the certificate signing request. The key and certificate of the gridadmin that would be called credentials can be read from a file as well from exported variables.
The script generated data to create csr serially i.e one after the another. The bulk process takes place for approval, issuance and retrieval part. The csr string is concatenated and then sent to the server for these processes.
The retrieved certificates are stored in separate files with a suffix of the serial number request in the bulk request processing i.e. (if the request is the third in the bulk request, it's certificate would be stored with '-3' suffix).
the write_cert function is purely designed to perform the string operations that are necessary to cleanse the certificate dump that we get and store them in different files as certificates.
The arguments are parsed using the optparse utility since it is compatible with python 2.4. Optparse doesn't handle the required options, hence the handling of the required options are done explicitly.
The key is written in pem format and the csr is base 64 encoded pkcs10 format encrypted using 2.48 bits RSA encryption using sha1 digest.
