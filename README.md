# I Need More Information
Check out our [RPC Firewall](https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/) blog post to gain better understanding of RPC, RPC attacks and the solution: the RPC Firewall.
For any questions, issues, or simlpy to shout out - we would love to hear from you! Contact us at [support@zeronetworks.com](mailto:support@zeronetworks.com)

# Why should I care?
RPC is the underlying mechanism which is used for numerous **lateral movement** techniques, **reconnaisense**, **relay** attacks, or simply to **exploit vulnerable RPC services**.

DCSync attack? over RPC. Remote DCOM? over RPC. WMIC? over RPC. SharpHound? over RPC. PetitPotam? over RPC. PsExec? over RPC. ZeroLogon? over RPC... well, you get the idea :)

# What is it used for?
## Research
Install the RPC Firewall and configure it to **audit** all remote RPC calls. 
Once executing any remote attack tools, you will see which RPC UUIDs and Opnums were called remotely.

## Remote RPC Attacks Detection
When the **RPC Firewall** is configured to audit, it write events to the Windows Event Log. 

Forward this log to your SIEM, and use it to create baselines of remote RPC traffic for your servers.

Once an abnormal RPC call is audited, use it to trigger an alert for your SOC team.

## Remote RPC Attacks Protection
The **RPC Firewall** can be configured to block & audit only potentially malicious RPC calls. All other RPC calls are not audited to reduce noise and improve performance.

Once a potentially malicious RPC call is detected, it is blocked and audited. This could be used to alert your SOC team, while keeping your servers protected.

# What are the RPC Firewall Components?
It is made up from 3 components:
1. **RpcFwManager.exe** - In charge of managing the RPC Firewall.
2. **RpcFirewall.dll**  - Injected DLL which performs the audit & filtering of RPC calls.
3. **RpcMessages.dll**  - A common library for sharing functions, and logic that writes data into Windows Event Viewer.

# How to use?
## Installing / Uninstalling 
Installation simply drops the RPC Firewall DLLs into the %SystemRoot%\System32, and configures the **RPCFWP** application log for the Event Viewer.

Make sure the event viewer is closed during install/uninstall.
```bash
RpcFwManager.exe /install
```

Uninstalling does the opposite.
```bash
RpcFwManager.exe /uninstall
```

## Protecting Process(es)
The RpcFwManager tried to inject the rpcFirewall.dll only to processes which have the RPCRT4.DLL loaded into them.

Once the rpcFirewall.dll is loaded, it verifies that the host process has a valid RPC interface, and is listening for remote connections. 

Otherwise, the rpcFirewall.dll unloaded itself from the target process.

If the process is a valid RPC server, the rpcFirewall starts to audit & monitor incoming RPC calls, according to the configuration file.

To protect a single process by pid:
```bash
RpcFwManager.exe /pid <pid>
```
To protect a single process by name:
```bash
RpcFwManager.exe /process <process name>
```
To protect all process, simply leave the <pid> or <process name> parametes blank.
```bash
RpcFwManager.exe /process
RpcFwManager.exe /pid
```
## Unprotecting Processes
To disable the RPC Firewall, either uninstall it, or use the unprotect parameter:
```bash
RpcFwManager.exe /unprotect
```
This will unload the rpcFirewall.dll from all processes.

## Persistency
RPC Firewall is not persistent on its own. 
One method of making sure that processes are continuesly protected is to create a scheduled task that executes a protection command. 
The following is a poweshell command which does just that, just replace <RPCFW_PATH> with the path actual path to the RPC Firewall release folder.

```bash
Register-ScheduledTask -TaskName "RPCFW" -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 60)) -User "NT AUTHORITY\SYSTEM" -Action (New-ScheduledTaskAction -Execute "rpcFwManager.exe" -Argument "/pid" -WorkingDirectory "<RPCFW_PATH>")
```

## Configuration
The rpcFwManager.exe looks for a **RpcFw.conf** file, in the same directory of the executable. 
This file uses the following configuration options: 
* uuid		->	match a specific uuid
* opnum		->	match a RPC opnum
* addr		->	match a remote IP address
* action	->	can be either **allow** or **block** (default allow) 
* audit		->	true or false, controls whether events are written to the RPCFWP log (default false)
* verbose	->	when true, outputs debug informaiton for specific RPC calls (default false)

The configuration order is important, as the first match determines the outcome of the RPC call.

For example, the following configuration will protect a DC from a DCSync attack by disabling the MS-DRSR UUID from non-domain machines. 
Also, notice that audit is enabled only for blocked MS-DRSR attempts, which could alert your SOC to a potential attack!
```bash
uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 addr:<dc_addr1> action:allow
uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 addr:<dc_addr2> action:allow
uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 action:block audit:true
```

Whenever the configuration changes, you need to notify the rpcFirewall.dll via the update command:
```bash
RpcFwManager.exe /update
```

## Viewing Logs
Open the Event Viewer -> Applications and Services Logs -> RPCFWP.

Add the Keywords column - this column would contain Audit Success/Failure.

# Can I Contribute?
Yes! Don't be shy to do a pull request. 

# I want RPC Firewall to do more things!
We want this also! please reach out to us with any thoughts, ideas or issues you are having: [support@zeronetworks.com](mailto:support@zeronetworks.com)

# Is there a License?
For more details see [LICENSE](LICENSE).
