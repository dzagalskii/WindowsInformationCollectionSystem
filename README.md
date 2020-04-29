# System of collection of information.
## Legend:

There is a computer network. There is a central computer to collect information about all other computers on the network. Information shall be collected automatically. To do this, an agent is implemented on all computers, which is the server part of the system. On the central kompyyu
The client part is started to request information. You must select whether the client or server initiates the transfer of information; Who is constantly working (ready to accept the request): client or server; Stateless or statefull server. To prove the offered architecture.

## Programs Overview:

- Use sockets (posix or WinSock but not wraps from MFC libraries or similar);
A separate request must exist for each type of information to be transmitted; The answer format should be formalized and suitable for machine processing, not just for human visual perception


## Server:

- Windows 7/8/10 all SPs;
- Console application without interactive interaction with the user;
- Diagnostic information (client connection/disconnection, requests received and processed) is displayed on the console;
- Parallel query processing diagram (Use Win32 termination ports).

## Client:

- Setting the server address;
- Specify the type of query;
- Inquiry initiation;
- Output of information sent by the server;
- Access rights output format shall include subject SID, subject name, types of set ACE, scope of set rights, numbers of set bits in the access mask, names of set bits for the current object type (in Russian or English or in the form of MSDN constant names);
- Object owner output format must contain SID and owner name;
- The current time and time since the OS startup should be displayed in seconds, minutes, hours, days, etc.

## Enciphering of transmitted data:

- All messages between client and server were transmitted in encrypted form, using CryptoAPI;
- Data must be transmitted using one of the session-key symmetric encryption algorithms;
- One of the asymmetric encryption algorithms must be used for the initial transmission of the session key.
