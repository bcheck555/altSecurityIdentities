# altSecurityIdentities
Populate altSecurityIdentities from Event Logs using this powershell script.

The script populates the altSecurityIdentities field with the X509IssuerSerialNumber mapping to satisfy the requirements of strong certificate mapping.

An alternative would be an explicit trust of the DoD certificates as shown:
https://dl.cyber.mil/pki-pke/pdf/unclass-qrg_msft_strong_name_mapping.pdf

https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

https://techcommunity.microsoft.com/blog/publicsectorblog/enable-strong-name-based-mapping-in-government-scenarios/4240402

The issue with relying solely on User Principal Names (UPNs) for certificate mapping stems from the inherent weaknesses associated with using easily replicable or modifiable attributes for critical authentication processes.

UPNs, like email addresses, are relatively easy to replicate or spoof compared to unique, non-reusable identifiers. This makes them less reliable for strong authentication.
If an attacker gains control of a system or Certificate Authority (CA), they could potentially issue certificates with forged UPNs.

Microsoft is pushing for "strong certificate mapping" to enhance security. This involves using more robust identifiers, such as the X509IssuerSerialNumber, which are unique and difficult to replicate.   
The move is designed to mitigate the risks associated with weak mapping methods, including those relying on UPNs.

The change in how certificate mapping is being handled within windows domain controllers, is being done to increase security.   
The use of attributes that can be easily replicated, such as the UPN, is considered a weak form of certificate mapping.   
Microsoft is moving toward strong certificate mapping, using attributes that are harder to replicate.   
Failure to adhere to the strong certificate mapping standards, will cause authentication failures.   
In essence, the move away from UPN-based mapping is a security-driven measure to ensure that certificates are reliably tied to legitimate users and devices, reducing the risk of unauthorized access.
