# Crowdstrike-Falcon-Queries
A few queries for hunting in Falcon

1. Initial Access: Phishing/Malicious Document Execution
#event_simpleName=ProcessRollup2
| in(ParentBaseFileName, values=["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"])
| in(FileName, values=["powershell.exe", "cmd.exe", "wmic.exe", "rundll32.exe", "mshta.exe", "certutil.exe"])
| CommandLine="* -enc*" OR CommandLine="* -EncodedCommand*" OR CommandLine="* /c *" OR CommandLine="* javascript:*"
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(-@timestamp)



2. Execution & Persistence: Scheduled Task Creation
#event_simpleName=ProcessRollup2
| FileName=schtasks.exe
| CommandLine="* /create *"
| table([@timestamp, ComputerName, UserName, CommandLine])
| sort(-@timestamp)




4. Privilege Escalation: LSASS Process Access
#event_simpleName=ProcessRollup2
| FileName="lsass.exe"
| join({
    #event_simpleName=ProcessRollup2
    | ParentBaseFileName="lsass.exe"
  }, field=TargetProcessId, key=ParentProcessId, mode=left, include=[FileName as ChildFileName, CommandLine as ChildCommandLine])
| where ChildFileName!=null
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ChildFileName, ChildCommandLine])
| sort(-@timestamp)




6. Defense Evasion: Disabling Security Tools
#event_simpleName=ProcessRollup2
| (FileName="sc.exe" OR FileName="net.exe")
| (CommandLine="* stop *" OR CommandLine="* delete *" OR CommandLine="* disable *")
| (CommandLine="*windefend*" OR CommandLine="*mrt.exe*" OR CommandLine="*defender*" OR CommandLine="*securitycenter*")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)




8. Credential Access: Password Dumps/Mimikatz
#event_simpleName=ProcessRollup2
| (FileName="mimikatz.exe" OR FileName="procdump.exe")
OR (CommandLine="*lsass.exe* dump*" OR CommandLine="*sekurlsa::logonpasswords*")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)




10. Discovery: Active Directory Reconnaissance
#event_simpleName=ProcessRollup2
| (FileName="nltest.exe" OR FileName="net.exe" OR FileName="whoami.exe" OR FileName="systeminfo.exe" OR FileName="dsquery.exe" OR FileName="adfind.exe" OR FileName="bloodhound.exe")
| (CommandLine="* /dclist*" OR CommandLine="* /domain*" OR CommandLine="* group *" OR CommandLine="* user *" OR CommandLine="* computers *" OR CommandLine="* /all *" OR CommandLine="* -f *" OR CommandLine="* -g *" OR CommandLine="* -u *")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)




12. Lateral Movement: Remote Service Creation/Execution
#event_simpleName=ProcessRollup2
| (FileName="sc.exe" OR FileName="psexec.exe" OR FileName="wmic.exe")
| (CommandLine="* \\\\* create *" OR CommandLine="* \\\\* service *" OR CommandLine="* /node:* process call create *")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)




14. Lateral Movement: Remote Desktop Protocol (RDP) Connections
#event_simpleName=UserLogon
| LogonType=10
| LocalAddressIP4!=null
| join({
    #event_simpleName=ProcessRollup2
    | FileName="mstsc.exe"
  }, field=ContextProcessId, key=TargetProcessId, mode=left, include=[CommandLine as MstscCommandLine])
| where MstscCommandLine!=null
| table([@timestamp, ComputerName, UserName, LocalAddressIP4, MstscCommandLine])
| sort(-@timestamp)




15. Exfiltration: Data Staging/Compression
#event_simpleName=ProcessRollup2
| (FileName="rar.exe" OR FileName="7z.exe" OR FileName="winzip.exe" OR FileName="tar.exe")
| (CommandLine="* a *" OR CommandLine="* -a *" OR CommandLine="* -cf *" OR CommandLine="* -cvf *")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)




17. Exfiltration: Unusual Outbound Network Connections to Cloud Storage/File Sharing
#event_simpleName=NetworkConnectIP4
| RemotePort=443
| join({
    #event_simpleName=DnsRequest
    | (DomainName="*dropbox.com*" OR DomainName="*onedrive.com*" OR DomainName="*mega.nz*" OR DomainName="*drive.google.com*")
  }, field=RemoteAddressIP4, key=ResolvedIP, mode=left, include=[DomainName])
| where DomainName!=null
| join({
    #event_simpleName=ProcessRollup2
  }, field=ContextProcessId, key=TargetProcessId, include=[FileName, CommandLine])
| table([@timestamp, ComputerName, FileName, CommandLine, RemoteAddressIP4, DomainName])
| sort(-@timestamp)





RED TEAM Activities
 Initial Access: Malicious Document Spawning PowerShell/CMD
#event_simpleName=ProcessRollup2
| in(ParentBaseFileName, values=["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"])
| in(FileName, values=["powershell.exe", "cmd.exe"])
| (CommandLine="* -enc*" OR CommandLine="* -EncodedCommand*" OR CommandLine="* /c *")
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(-@timestamp)



2. Execution & Persistence: Scheduled Task Creation by Non-System Accounts
#event_simpleName=ProcessRollup2
| FileName="schtasks.exe"
| CommandLine="* /create *"
| UserName!="NT AUTHORITY\\SYSTEM" AND UserName!="NT AUTHORITY\\LOCAL SERVICE" AND UserName!="NT AUTHORITY\\NETWORK SERVICE"
| table([@timestamp, ComputerName, UserName, CommandLine])
| sort(-@timestamp)



4. Privilege Escalation: LSASS Process Access for Credential Dumping
#event_simpleName=ProcessRollup2
| FileName="lsass.exe"
| join({
    #event_simpleName=ProcessRollup2
    | ParentBaseFileName="lsass.exe"
  }, field=TargetProcessId, key=ParentProcessId, mode=left, include=[FileName as ChildFileName, CommandLine as ChildCommandLine])
| where ChildFileName!=null AND !in(ChildFileName, values=["taskmgr.exe", "procexp.exe"])
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ChildFileName, ChildCommandLine])
| sort(-@timestamp)



6. Defense Evasion: Disabling Windows Defender or Security Services
#event_simpleName=ProcessRollup2
| (FileName="sc.exe" OR FileName="net.exe")
| (CommandLine="* stop *" OR CommandLine="* disable *" OR CommandLine="* delete *")
| (CommandLine="*WinDefend*" OR CommandLine="*MsMpEng.exe*" OR CommandLine="*SecurityHealthService*")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)



8. Credential Access: Execution of Known Credential Dumping Tools
#event_simpleName=ProcessRollup2
| (FileName="mimikatz.exe" OR FileName="procdump.exe" OR FileName="hashdump.exe" OR FileName="lazagne.exe")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)



10. Discovery: Active Directory Reconnaissance with Common Tools
#event_simpleName=ProcessRollup2
| in(FileName, values=["nltest.exe", "net.exe", "whoami.exe", "systeminfo.exe", "dsquery.exe", "adfind.exe", "bloodhound.exe", "powerView.ps1", "sharphound.exe"])
| (CommandLine="* /dclist*" OR CommandLine="* /domain*" OR CommandLine="* group *" OR CommandLine="* user *" OR CommandLine="* computers *" OR CommandLine="* /all *" OR CommandLine="* -f *" OR CommandLine="* -g *" OR CommandLine="* -u *" OR CommandLine="* -Domain *")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)



12. Lateral Movement: Remote Service Creation via PsExec/WMIC/SC
#event_simpleName=ProcessRollup2
| (FileName="psexec.exe" OR FileName="wmic.exe" OR FileName="sc.exe")
| (CommandLine="* \\\\* create *" OR CommandLine="* \\\\* service *" OR CommandLine="* /node:* process call create *")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)




14. Lateral Movement: Suspicious RDP Logons from Unusual Sources
#event_simpleName=UserLogon
| LogonType=10
| LocalAddressIP4!=null
| join({
    #event_simpleName=NetworkConnectIP4
    | ConnectionDirection="Inbound"
    | RemotePort=3389
  }, field=LocalAddressIP4, key=LocalAddressIP4, mode=left, include=[RemoteAddressIP4 as RDP_Source_IP])
| where RDP_Source_IP!=null
| groupBy([UserName, ComputerName, LocalAddressIP4, RDP_Source_IP], function=count(as=logon_count))
| logon_count <= 2
| table([@timestamp, ComputerName, UserName, LocalAddressIP4, RDP_Source_IP, logon_count])
| sort(-@timestamp)



16. Collection: Data Staging with Archiving Tools
#event_simpleName=ProcessRollup2
| in(FileName, values=["rar.exe", "7z.exe", "winzip.exe", "tar.exe", "zip.exe"])
| (CommandLine="* a *" OR CommandLine="* -a *" OR CommandLine="* -cf *" OR CommandLine="* -cvf *" OR CommandLine="* -m *")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)



17. Exfiltration: Outbound Connections to Cloud Storage/File Sharing Services
#event_simpleName=NetworkConnectIP4
| RemotePort=443
| join({
    #event_simpleName=DnsRequest
    | (DomainName="*dropbox.com*" OR DomainName="*onedrive.com*" OR DomainName="*mega.nz*" OR DomainName="*drive.google.com*" OR DomainName="*s3.amazonaws.com*" OR DomainName="*blob.core.windows.net*")
  }, field=RemoteAddressIP4, key=ResolvedIP, mode=left, include=[DomainName])
| where DomainName!=null
| join({
    #event_simpleName=ProcessRollup2
  }, field=ContextProcessId, key=TargetProcessId, include=[FileName, CommandLine])
| table([@timestamp, ComputerName, FileName, CommandLine, RemoteAddressIP4, DomainName])
| sort(-@timestamp)









 Deep Web Searching
1. DNS Requests to Known Dark Web Domains/TLDs
#event_simpleName=DnsRequest
| (DomainName="*.onion*" OR DomainName="*.i2p*" OR DomainName="*.bit*" OR DomainName="*.liberty*" OR DomainName="*.bazar*" OR DomainName="*.coin*" OR DomainName="*.emc*" OR DomainName="*.free*" OR DomainName="*.fur*" OR DomainName="*.geek*" OR DomainName="*.gopher*" OR DomainName="*.indy*" OR DomainName="*.lite*" OR DomainName="*.mesh*" OR DomainName="*.null*" OR DomainName="*.oss*" OR DomainName="*.oz*" OR DomainName="*.parody*" OR DomainName="*.pirate*" OR DomainName="*.dyn*" OR DomainName="*.tor*" OR DomainName="*.zkey*")
| join({
    #event_simpleName=ProcessRollup2
  }, field=ContextProcessId, key=TargetProcessId, include=[FileName, CommandLine, UserName])
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, DomainName])
| sort(-@timestamp)
This query directly hunts for DNS requests to domains associated with various dark web networks (e.g., Tor's .onion, I2P's .i2p, Namecoin's .bit). It then enriches these events with process information to identify which application initiated the request.
2. Network Connections to Non-Standard Ports Associated with Dark Web Tools
#event_simpleName=NetworkConnectIP4
| in(RemotePort, values=[9001, 9030, 9050, 9101, 9102, 9103, 9104, 9105, 9106, 9107, 9108, 9109, 9110, 9111, 9112, 9113, 9114, 9115, 9116, 9117, 9118, 9119, 9120, 9121, 9122, 9123, 9124, 9125, 9126, 9127, 9128, 9129, 9130, 9131, 9132, 9133, 9134, 9135, 9136, 9137, 9138, 9139, 9140, 9141, 9142, 9143, 9144, 9145, 9146, 9147, 9148, 9149, 9150, 9151, 9152, 9153, 9154, 9155, 9156, 9157, 9158, 9159, 9160, 9161, 9162, 9163, 9164, 9165, 9166, 9167, 9168, 9169, 9170, 9171, 9172, 9173, 9174, 9175, 9176, 9177, 9178, 9179, 9180, 9181, 9182, 9183, 9184, 9185, 9186, 9187, 9188, 9189, 9190, 9191, 9192, 9193, 9194, 9195, 9196, 9197, 9198, 9199, 9200, 9201, 9202, 9203, 9204, 9205, 9206, 9207, 9208, 9209, 9210, 9211, 9212, 9213, 9214, 9215, 9216, 9217, 9218, 9219, 9220, 9221, 9222, 9223, 9224, 9225, 9226, 9227, 9228, 9229, 9230, 9231, 9232, 9233, 9234, 9235, 9236, 9237, 9238, 9239, 9240, 9241, 9242, 9243, 9244, 9245, 9246, 9247, 9248, 9249, 9250, 9251, 9252, 9253, 9254, 9255, 9256, 9257, 9258, 9259, 9260, 9261, 9262, 9263, 9264, 9265, 9266, 9267, 9268, 9269, 9270, 9271, 9272, 9273, 9274, 9275, 9276, 9277, 9278, 9279, 9280, 9281, 9282, 9283, 9284, 9285, 9286, 9287, 9288, 9289, 9290, 9291, 9292, 9293, 9294, 9295, 9296, 9297, 9298, 9299, 9300, 9301, 9302, 9303, 9304, 9305, 9306, 9307, 9308, 9309, 9310, 9311, 9312, 9313, 9314, 9315, 9316, 9317, 9318, 9319, 9320, 9321, 9322, 9323, 9324, 9325, 9326, 9327, 9328, 9329, 9330, 9331, 9332, 9333, 9334, 9335, 9336, 9337, 9338, 9339, 9340, 9341, 9342, 9343, 9344, 9345, 9346, 9347, 9348, 9349, 9350, 9351, 9352, 9353, 9354, 9355, 9356, 9357, 9358, 9359, 9360, 9361, 9362, 9363, 9364, 9365, 9366, 9367, 9368, 9369, 9370, 9371, 9372, 9373, 9374, 9375, 9376, 9377, 9378, 9379, 9380, 9381, 9382, 9383, 9384, 9385, 9386, 9387, 9388, 9389, 9390, 9391, 9392, 9393, 9394, 9395, 9396, 9397, 9398, 9399, 9400, 9401, 9402, 9403, 9404, 9405, 9406, 9407, 9408, 9409, 9410, 9411, 9412, 9413, 9414, 9415, 9416, 9417, 9418, 9419, 9420, 9421, 9422, 9423, 9424, 9425, 9426, 9427, 9428, 9429, 9430, 9431, 9432, 9433, 9434, 9435, 9436, 9437, 9438, 9439, 9440, 9441, 9442, 9443, 9444, 9445, 9446, 9447, 9448, 9449, 9450, 9451, 9452, 9453, 9454, 9455, 9456, 9457, 9458, 9459, 9460, 9461, 9462, 9463, 9464, 9465, 9466, 9467, 9468, 9469, 9470, 9471, 9472, 9473, 9474, 9475, 9476, 9477, 9478, 9479, 9480, 9481, 9482, 9483, 9484, 9485, 9486, 9487, 9488, 9489, 9490, 9491, 9492, 9493, 9494, 9495, 9496, 9497, 9498, 9499, 9500, 9501, 9502, 9503, 9504, 9505, 9506, 9507, 9508, 9509, 9510, 9511, 9512, 9513, 9514, 9515, 9516, 9517, 9518, 9519, 9520, 9521, 9522, 9523, 9524, 9525, 9526, 9527, 9528, 9529, 9530, 9531, 9532, 9533, 9534, 9535, 9536, 9537, 9538, 9539, 9540, 9541, 9542, 9543, 9544, 9545, 9546, 9547, 9548, 9549, 9550, 9551, 9552, 9553, 9554, 9555, 9556, 9557, 9558, 9559, 9560, 9561, 9562, 9563, 9564, 9565, 9566, 9567, 9568, 9569, 9570, 9571, 9572, 9573, 9574, 9575, 9576, 9577, 9578, 9579, 9580, 9581, 9582, 9583, 9584, 9585, 9586, 9587, 9588, 9589, 9590, 9591, 9592, 9593, 9594, 9595, 9596, 9597, 9598, 9599, 9600, 9601, 9602, 9603, 9604, 9605, 9606, 9607, 9608, 9609, 9610, 9611, 9612, 9613, 9614, 9615, 9616, 9617, 9618, 9619, 9620, 9621, 9622, 9623, 9624, 9625, 9626, 9627, 9628, 9629, 9630, 9631, 9632, 9633, 9634, 9635, 9636, 9637, 9638, 9639, 9640, 9641, 9642, 9643, 9644, 9645, 9646, 9647, 9648, 9649, 9650, 9651, 9652, 9653, 9654, 9655, 9656, 9657, 9658, 9659, 9660, 9661, 9662, 9663, 9664, 9665, 9666, 9667, 9668, 9669, 9670, 9671, 9672, 9673, 9674, 9675, 9676, 9677, 9678, 9679, 9680, 9681, 9682, 9683, 9684, 9685, 9686, 9687, 9688, 9689, 9690, 9691, 9692, 9693, 9694, 9695, 9696, 9697, 9698, 9699, 9700, 9701, 9702, 9703, 9704, 9705, 9706, 9707, 9708, 9709, 9710, 9711, 9712, 9713, 9714, 9715, 9716, 9717, 9718, 9719, 9720, 9721, 9722, 9723, 9724, 9725, 9726, 9727, 9728, 9729, 9730, 9731, 9732, 9733, 9734, 9735, 9736, 9737, 9738, 9739, 9740, 9741, 9742, 9743, 9744, 9745, 9746, 9747, 9748, 9749, 9750, 9751, 9752, 9753, 9754, 9755, 9756, 9757, 9758, 9759, 9760, 9761, 9762, 9763, 9764, 9765, 9766, 9767, 9768, 9769, 9770, 9771, 9772, 9773, 9774, 9775, 9776, 9777, 9778, 9779, 9780, 9781, 9782, 9783, 9784, 9785, 9786, 9787, 9788, 9789, 9790, 9791, 9792, 9793, 9794, 9795, 9796, 9797, 9798, 9799, 9800, 9801, 9802, 9803, 9804, 9805, 9806, 9807, 9808, 9809, 9810, 9811, 9812, 9813, 9814, 9815, 9816, 9817, 9818, 9819, 9820, 9821, 9822, 9823, 9824, 9825, 9826, 9827, 9828, 9829, 9830, 9831, 9832, 9833, 9834, 9835, 9836, 9837, 9838, 9839, 9840, 9841, 9842, 9843, 9844, 9845, 9846, 9847, 9848, 9849, 9850, 9851, 9852, 9853, 9854, 9855, 9856, 9857, 9858, 9859, 9860, 9861, 9862, 9863, 9864, 9865, 9866, 9867, 9868, 9869, 9870, 9871, 9872, 9873, 9874, 9875, 9876, 9877, 9878, 9879, 9880, 9881, 9882, 9883, 9884, 9885, 9886, 9887, 9888, 9889, 9890, 9891, 9892, 9893, 9894, 9895, 9896, 9897, 9898, 9899, 9900, 9901, 9902, 9903, 9904, 9905, 9906, 9907, 9908, 9909, 9910, 9911, 9912, 9913, 9914, 9915, 9916, 9917, 9918, 9919, 9920, 9921, 9922, 9923, 9924, 9925, 9926, 9927, 9928, 9929, 9930, 9931, 9932, 9933, 9934, 9935, 9936, 9937, 9938, 9939, 9940, 9941, 9942, 9943, 9944, 9945, 9946, 9947, 9948, 9949, 9950, 9951, 9952, 9953, 9954, 9955, 9956, 9957, 9958, 9959, 9960, 9961, 9962, 9963, 9964, 9965, 9966, 9967, 9968, 9969, 9970, 9971, 9972, 9973, 9974, 9975, 9976, 9977, 9978, 9979, 9980, 9981, 9982, 9983, 9984, 9985, 9986, 9987, 9988, 9989, 9990, 9991, 9992, 9993, 9994, 9995, 9996, 9997, 9998, 9999])
| join({
    #event_simpleName=ProcessRollup2
  }, field=ContextProcessId, key=TargetProcessId, include=[FileName, CommandLine, UserName])
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, RemoteAddressIP4, RemotePort])
| sort(-@timestamp)
This query looks for network connections on non-standard ports that are commonly used by dark web tools like Tor (e.g., 9001, 9030, 9050) or other peer-to-peer networks. It then correlates these connections with the process that initiated them.
3. Execution of Known Dark Web Browsers/Tools
#event_simpleName=ProcessRollup2
| (FileName="tor.exe" OR FileName="torbrowser.exe" OR FileName="i2p.exe" OR FileName="freenet.exe" OR FileName="tormini.exe" OR FileName="tbb.exe" OR FileName="brave.exe" AND CommandLine="*--tor*")
| table([@timestamp, ComputerName, UserName, FileName, CommandLine])
| sort(-@timestamp)


5. File System Activity Related to Dark Web Tools (Installation/Configuration)
#event_simpleName=FileCreate OR #event_simpleName=FileWrite
| (FilePath="*\\Tor Browser\\*" OR FilePath="*\\i2p\\*" OR FilePath="*\\freenet\\*" OR FilePath="*\\darknet\\*" OR FilePath="*\\onion\\*" OR FileName="torrc" OR FileName="i2p.conf" OR FileName="freenet.ini")
| join({
    #event_simpleName=ProcessRollup2
  }, field=ContextProcessId, key=TargetProcessId, mode=left, include=[FileName as CreatingProcess, CommandLine as CreatingCommandLine])
| table([@timestamp, ComputerName, UserName, CreatingProcess, CreatingCommandLine, FilePath, FileName])
| sort(-@timestamp)


7. Unusual Outbound Traffic Volume to Uncategorized/High-Risk Geolocation IPs
#event_simpleName=NetworkConnectIP4
| ConnectionDirection="Outbound"
| RemoteAddressIP4!=null
| join({
    #event_simpleName=GeoIP
    | !in(Country, values=["US", "CA", "GB", "DE", "FR", "AU"]) // Exclude common trusted countries
    | !in(Category, values=["Business", "Cloud", "CDN"]) // Exclude common legitimate categories
  }, field=RemoteAddressIP4, key=IPAddress, mode=left, include=[Country, Category])
| where Country!=null AND Category!=null
| groupBy([ComputerName, RemoteAddressIP4, Country, Category], function=count(as=connection_count))
| connection_count > 100 // Threshold for unusual volume
| table([@timestamp, ComputerName, RemoteAddressIP4, Country, Category, connection_count])
| sort(-@timestamp)




Phishing:
1. Phishing: Malicious Document Spawning Suspicious Processes
#event_simpleName=ProcessRollup2
| in(ParentBaseFileName, values=["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"])
| in(FileName, values=["powershell.exe", "cmd.exe", "wmic.exe", "rundll32.exe", "mshta.exe", "certutil.exe"])
| (CommandLine="* -enc*" OR CommandLine="* -EncodedCommand*" OR CommandLine="* /c *" OR CommandLine="* javascript:*" OR CommandLine="* http*")
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(-@timestamp)

3. Phishing: Email Client Spawning Network Connections to Unusual Domains
#event_simpleName=NetworkConnectIP4
| in(ContextProcessId, (
    #event_simpleName=ProcessRollup2
    | in(FileName, values=["outlook.exe", "thunderbird.exe"])
    | select(TargetProcessId)
))
| RemotePort=80 OR RemotePort=443
| join({
    #event_simpleName=DnsRequest
    | DomainName!=null
    | !in(DomainName, values=["*.microsoft.com", "*.google.com", "*.outlook.com", "*.live.com", "*.office.com"]) // Exclude common email domains
    | groupBy(DomainName, function=count(as=domain_count))
    | domain_count <= 5 // Look for rare domains
  }, field=RemoteAddressIP4, key=ResolvedIP, mode=left, include=[DomainName, domain_count])
| where DomainName!=null AND domain_count <= 5
| join({
    #event_simpleName=ProcessRollup2
  }, field=ContextProcessId, key=TargetProcessId, include=[FileName, CommandLine, UserName])
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, RemoteAddressIP4, RemotePort, DomainName, domain_count])
| sort(-@timestamp)

5. Phishing: Browser Downloading Executables from Non-Reputable Sources
#event_simpleName=FileCreate
| in(FileName, values=["*.exe", "*.dll", "*.msi", "*.hta", "*.js", "*.vbs", "*.ps1"])
| join({
    #event_simpleName=ProcessRollup2
    | in(FileName, values=["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"])
    | select(TargetProcessId)
  }, field=ContextProcessId, key=TargetProcessId, mode=left, include=[FileName as BrowserFileName, CommandLine as BrowserCommandLine])
| where BrowserFileName!=null
| join({
    #event_simpleName=NetworkConnectIP4
    | RemotePort=80 OR RemotePort=443
    | join({
        #event_simpleName=DnsRequest
        | DomainName!=null
        | !in(DomainName, values=["*.microsoft.com", "*.google.com", "*.adobe.com", "*.update.microsoft.com"]) // Exclude common trusted download sources
        | groupBy(DomainName, function=count(as=domain_count))
        | domain_count <= 10 // Look for less common download sources
      }, field=RemoteAddressIP4, key=ResolvedIP, mode=left, include=[DomainName, domain_count])
    | where DomainName!=null AND domain_count <= 10
    | select([ContextProcessId, DomainName])
  }, field=ContextProcessId, key=ContextProcessId, mode=left, include=[DomainName as DownloadSourceDomain])
| where DownloadSourceDomain!=null
| table([@timestamp, ComputerName, UserName, BrowserFileName, BrowserCommandLine, FileName, FilePath, DownloadSourceDomain])
| sort(-@timestamp)



6. Phishing: User Logon from Geographically Unusual Location After Clicking a Link
#event_simpleName=UserLogon
| LogonType=10 // Remote Interactive Logon (e.g., RDP, VPN)
| join({
    #event_simpleName=NetworkConnectIP4
    | ConnectionDirection="Outbound"
    | RemotePort=80 OR RemotePort=443
    | join({
        #event_simpleName=ProcessRollup2
        | in(FileName, values=["outlook.exe", "thunderbird.exe", "chrome.exe", "firefox.exe", "msedge.exe"])
        | select(TargetProcessId, UserName)
      }, field=ContextProcessId, key=TargetProcessId, include=[UserName as ClickerUser])
    | where ClickerUser!=null
    | join({
        #event_simpleName=GeoIP
        | Country!=null
      }, field=RemoteAddressIP4, key=IPAddress, mode=left, include=[Country as ClickedCountry])
    | where ClickedCountry!=null
    | select([ClickerUser, ClickedCountry, @timestamp as ClickTime])
  }, field=UserName, key=ClickerUser, mode=left, include=[ClickedCountry, ClickTime])
| where ClickedCountry!=null AND ClickedCountry!=Country // Compare logon country with clicked link country
| join({
    #event_simpleName=GeoIP
    | Country!=null
  }, field=LocalAddressIP4, key=IPAddress, mode=left, include=[Country as LogonCountry])
| where LogonCountry!=null
| table([@timestamp, ComputerName, UserName, LogonCountry, ClickedCountry, ClickTime])
| sort(-@timestamp)











#event_simpleName=ProcessRollup2
| in(FileName, values=["powershell.exe", "pwsh.exe"])
| CommandLine=*-enc* OR CommandLine=*-EncodedCommand* OR CommandLine="*-e *"
| table([@timestamp, ComputerName, UserName, CommandLine], limit=50, sortby=@timestamp, order=desc)

2. Outbound Connections to Non-Standard Ports
#event_simpleName=NetworkConnectIP4
| !in(RemotePort, values=[80, 443, 53, 22, 445, 3389])
| groupBy([RemoteAddressIP4, RemotePort], function=[count(as=total), count(ComputerName, distinct=true, as=unique_hosts)])
| sort(field=total, order=desc, limit=25)

4. DNS Requests Correlated with Process
#event_simpleName=DnsRequest
| join({
    #event_simpleName=ProcessRollup2
  }, field=ContextProcessId, key=TargetProcessId, include=[FileName, CommandLine])
| groupBy([DomainName, FileName], function=count())
| sort(field=_count, order=desc, limit=50)


#repo=base_sensor  #event_simpleName=ZipFileWritten

FileName=/(txt|pdf|doc|docm|ppt|html)\.zip/i

| groupBy([#event_simpleName, @timestampt, FileName],function =(count(FileName, as=FileNameCount)))


 File Deletion Events for .key Files
#event_simpleName=FileDelete
| FileName="*.key" OR TargetFileName="*.key"
| table([@timestamp, ComputerName, UserName, FileName, TargetFileName, ImageFileName, CommandLine], limit=100, sortby=@timestamp, order=desc)

2. Process Executions Deleting .key Files
#event_simpleName=ProcessRollup2
| CommandLine="*del *.key*" OR CommandLine="*rm *.key*" OR CommandLine="*erase *.key*"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine], limit=100, sortby=@timestamp, order=desc)
3. File Modification Events Indicating .key File Overwrites or Truncations
#event_simpleName=FileModification
| FileName="*.key" OR TargetFileName="*.key"
| FileOperation="Overwrite" OR FileOperation="Truncate"
| table([@timestamp, ComputerName, UserName, FileName, TargetFileName, FileOperation, ImageFileName, CommandLine], limit=100, sortby=@timestamp, order=desc)

#event_simpleName=ProcessRollup2
| CommandLine="*del *.key*" OR CommandLine="*rm *.key*" OR CommandLine="*erase *.key*" ComputerName=*
| table([@timestamp, ComputerName, UserName, FileName, CommandLine], limit=100, sortby=@timestamp, order=desc) 




 WEB EXPLOTATION
1. Web Server Process Spawning Suspicious Child Processes
#event_simpleName=ProcessRollup2
| in(ParentBaseFileName, values=["apache.exe", "nginx.exe", "w3wp.exe", "httpd.exe"])
| in(FileName, values=["cmd.exe", "powershell.exe", "pwsh.exe", "sh.exe", "bash.exe", "python.exe", "perl.exe", "php.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe", "wscript.exe", "cscript.exe"])
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=100, sortby=@timestamp, order=desc)

3. Outbound Network Connections from Web Server Processes to Unusual Ports/IPs
#event_simpleName=NetworkConnectIP4
| in(ContextProcessFileName, values=["apache.exe", "nginx.exe", "w3wp.exe", "httpd.exe"])
| !in(RemotePort, values=[80, 443])
| groupBy([ComputerName, ContextProcessFileName, RemoteAddressIP4, RemotePort], function=[count(as=total_connections), count(ContextProcessId, distinct=true, as=unique_processes)])
| total_connections >= 5
| sort(field=total_connections, order=desc, limit=50)

5. Web Server Process Writing Executable Files to Web Directories
#event_simpleName=FileCreation
| in(ImageFileName, values=["apache.exe", "nginx.exe", "w3wp.exe", "httpd.exe"])
| TargetFileName="*.php" OR TargetFileName="*.asp" OR TargetFileName="*.aspx" OR TargetFileName="*.jsp" OR TargetFileName="*.cgi" OR TargetFileName="*.pl"
| TargetFilePath="*\\wwwroot\\*" OR TargetFilePath="*\\htdocs\\*" OR TargetFilePath="*\\webapps\\*" OR TargetFilePath="*\\html\\*"
| table([@timestamp, ComputerName, UserName, ImageFileName, TargetFileName, TargetFilePath], limit=100, sortby=@timestamp, order=desc)

7. Suspicious Command Line Arguments in Web Server Child Processes
#event_simpleName=ProcessRollup2
| in(ParentBaseFileName, values=["apache.exe", "nginx.exe", "w3wp.exe", "httpd.exe"])
| CommandLine="*wget*" OR CommandLine="*curl*" OR CommandLine="*nc -l -p*" OR CommandLine="*ncat -l -p*" OR CommandLine="*base64 -d*" OR CommandLine="*echo *" OR CommandLine="*system(" OR CommandLine="*exec(" OR CommandLine="*passthru(" OR CommandLine="*shell_exec("
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=100, sortby=@timestamp, order=desc)

9. Unusual File Modifications in Web Directories
#event_simpleName=FileModification
| TargetFilePath="*\\wwwroot\\*" OR TargetFilePath="*\\htdocs\\*" OR TargetFilePath="*\\webapps\\*" OR TargetFilePath="*\\html\\*"
| !in(ImageFileName, values=["apache.exe", "nginx.exe", "w3wp.exe", "httpd.exe", "vs_installer.exe", "devenv.exe", "msbuild.exe"]) // Exclude legitimate web server/development tools
| table([@timestamp, ComputerName, UserName, ImageFileName, TargetFileName, TargetFilePath, FileOperation], limit=100, sortby=@timestamp, order=desc)

11. DNS Requests from Web Server Processes to Rare/Suspicious Domains
#event_simpleName=DnsRequest
| in(ContextProcessFileName, values=["apache.exe", "nginx.exe", "w3wp.exe", "httpd.exe"])
| regex("(?<subdomain>[a-z0-9]{15,})\\.(?<tld>[a-z]{2,5})$", field=DomainName) // Detect potential DGA domains
| groupBy([ComputerName, ContextProcessFileName, DomainName], function=[count(as=total_requests), count(ContextProcessId, distinct=true, as=unique_processes)])
| total_requests <= 3 // Look for low volume, potentially unique domains
| sort(field=total_requests, order=asc, limit=50)

13. Process Accessing Sensitive Configuration Files from Web Server Processes
#event_simpleName=FileRead
| in(ImageFileName, values=["apache.exe", "nginx.exe", "w3wp.exe", "httpd.exe"])
| TargetFileName="*config.php" OR TargetFileName="*web.config" OR TargetFileName="*settings.py" OR TargetFileName="*database.yml" OR TargetFileName="*wp-config.php" OR TargetFileName="*.env" OR TargetFileName="*credentials*"
| table([@timestamp, ComputerName, UserName, ImageFileName, TargetFileName, TargetFilePath], limit=100, sortby=@timestamp, order=desc)

14. Execution of Obfuscated Scripts by Web Server Processes
#event_simpleName=ProcessRollup2
| in(ParentBaseFileName, values=["apache.exe", "nginx.exe", "w3wp.exe", "httpd.exe"])
| CommandLine="*eval(*" OR CommandLine="*base64_decode(*" OR CommandLine="*gzinflate(*" OR CommandLine="*str_rot13(*" OR CommandLine="*chr(*" OR CommandLine="*unserialize(*"
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], 


Svchost.exe Making Outbound Network Connections
#event_simpleName=NetworkConnectIP4
| FileName="svchost.exe"
| !in(RemotePort, values=[53, 88, 135, 389, 445, 464, 636, 3268, 3269, 49152-65535]) // Exclude common ports for legitimate svchost activity
| !in(RemoteAddressIP4, values=["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]) // Exclude internal/loopback
| groupBy([ComputerName, RemoteAddressIP4, RemotePort, ContextProcessId], function=count())
| sort(field=_count, order=desc, limit=50)

2. Notepad.exe or Other Common Applications Making Outbound Network Connections
#event_simpleName=NetworkConnectIP4
| in(FileName, values=["notepad.exe", "calc.exe", "mspaint.exe", "write.exe", "explorer.exe"]) // Add other applications that shouldn't connect
| !in(RemoteAddressIP4, values=["127.0.0.1"]) // Exclude loopback
| groupBy([ComputerName, FileName, RemoteAddressIP4, RemotePort, ContextProcessId], function=count())
| sort(field=_count, order=desc, limit=50)

4. Microsoft Office Applications Making Outbound Network Connections to Unusual Destinations
#event_simpleName=NetworkConnectIP4
| in(FileName, values=["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE"])
| !in(RemotePort, values=[80, 443]) // Exclude standard web ports for updates/legitimate cloud services
| !in(RemoteAddressIP4, values=["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]) // Exclude internal/loopback
| groupBy([ComputerName, FileName, RemoteAddressIP4, RemotePort, ContextProcessId], function=count())
| sort(field=_count, order=desc, limit=50)

6. System Processes (e.g., lsass.exe, services.exe) Making Outbound Network Connections
#event_simpleName=NetworkConnectIP4
| in(FileName, values=["lsass.exe", "services.exe", "winlogon.exe", "csrss.exe"])
| !in(RemoteAddressIP4, values=["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]) // Exclude internal/loopback
| groupBy([ComputerName, FileName, RemoteAddressIP4, RemotePort, ContextProcessId], function=count())
| sort(field=_count, order=desc, limit=50)

8. Processes in C:\Windows\Temp or User AppData Directories Making Outbound Connections
#event_simpleName=NetworkConnectIP4
| ImageFileName="C:\\Windows\\Temp\\*" OR ImageFileName="*\\AppData\\Local\\Temp\\*" OR ImageFileName="*\\AppData\\Roaming\\*"
| !in(RemoteAddressIP4, values=["127.0.0.1"]) // Exclude loopback
| groupBy([ComputerName, ImageFileName, RemoteAddressIP4, RemotePort, ContextProcessId], function=count())
| sort(field=_count, order=desc, limit=50)

10. Processes with No Known Publisher or Digital Signature Making Outbound Connections
#event_simpleName=NetworkConnectIP4
| !ImageFilePublisher=* AND !ImageFileSigner=*
| !in(RemoteAddressIP4, values=["127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]) // Exclude internal/loopback
| groupBy([ComputerName, FileName, RemoteAddressIP4, RemotePort, ContextProcessId], function=count())
| sort(field=_count, order=desc, limit=50)

12. Processes with Unusual CommandLine Arguments Making Outbound Connections
#event_simpleName=NetworkConnectIP4
| CommandLine="*powershell -enc*" OR CommandLine="*cmd /c*" OR CommandLine="*bitsadmin /transfer*" OR CommandLine="*certutil -urlcache*"
| !in(RemoteAddressIP4, values=["127.0.0.1"]) // Exclude loopback
| groupBy([ComputerName, FileName, CommandLine, RemoteAddressIP4, RemotePort, ContextProcessId], function=count())
| sort(field=_count, order=desc, limit=50)


T1055: Process Injection
Process injection involves running custom code in the address space of another process. This can be used to evade defenses, elevate privileges, or hide malicious activity. Detecting it often relies on identifying anomalous process behavior.
1. Orphaned Processes (Missing Parent Process)
#event_simpleName=ProcessRollup2
| ParentProcessId=null OR ParentBaseFileName=null
| table([@timestamp, ComputerName, FileName, ImageFileName, UserName, TargetProcessId, CommandLine], limit=100, sortby=@timestamp, order=desc)

3. Processes with Mismatched Parent-Child Executables
#event_simpleName=ProcessRollup2
| eval(parent_exe = lower(ParentBaseFileName))
| eval(child_exe = lower(FileName))
| parent_exe != child_exe
| in(parent_exe, values=["explorer.exe", "svchost.exe", "winlogon.exe", "services.exe"]) // Common injection targets
| in(child_exe, values=["powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe"]) // Common injected executables
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine], limit=100, sortby=@timestamp, order=desc)

5. Processes Writing to Executable Memory Regions (Advanced - Requires specific sensor visibility)
#event_simpleName=MemoryWrite
| ProtectionFlags="PAGE_EXECUTE_READWRITE" OR ProtectionFlags="PAGE_EXECUTE_READ" OR ProtectionFlags="PAGE_EXECUTE_WRITECOPY"
| !in(FileName, values=["csrss.exe", "lsass.exe", "winlogon.exe"]) // Exclude common false positives for memory writes
| table([@timestamp, ComputerName, FileName, ImageFileName, TargetProcessId, ProtectionFlags, WriteAddress], limit=100, sortby=@timestamp, order=desc)

7. Unusual DLL Loads by Legitimate Processes
#event_simpleName=ModuleLoad
| in(FileName, values=["explorer.exe", "svchost.exe", "winlogon.exe", "services.exe"]) // Common injection targets
| ImageFileName!="C:\\Windows\\System32\\*.dll" AND ImageFileName!="C:\\Windows\\SysWOW64\\*.dll" // Exclude legitimate system DLLs
| table([@timestamp, ComputerName, FileName, ImageFileName, ModuleFileName, ModuleBaseAddress], limit=100, sortby=@timestamp, order=desc)

T1105: Ingress Tool Transfer

1. Download Utilities Executing with Suspicious Command Lines
#event_simpleName=ProcessRollup2
| in(FileName, values=["bitsadmin.exe", "certutil.exe", "powershell.exe", "curl.exe", "wget.exe"])
| CommandLine="*download*" OR CommandLine="*urlcache*" OR CommandLine="*transfer*" OR CommandLine="*webclient*" OR CommandLine="*System.Net.WebClient*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*iwr*"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=100, sortby=@timestamp, order=desc)

3. Network Connections to Known File Sharing/Cloud Storage Services by Unusual Processes
#event_simpleName=NetworkConnectIP4
| in(RemoteAddressIP4, values=["<IP_of_known_malicious_server>", "<IP_of_C2_server>"]) // Replace with known malicious IPs
| in(DomainName, values=["dropbox.com", "onedrive.live.com", "drive.google.com", "mega.nz"]) // Common cloud storage
| !in(FileName, values=["chrome.exe", "firefox.exe", "msedge.exe"]) // Exclude legitimate browsers
| table([@timestamp, ComputerName, UserName, FileName, RemoteAddressIP4, RemotePort, DomainName], limit=100, sortby=@timestamp, order=desc)

5. Executables Created in Temporary or User-Writable Directories
#event_simpleName=FileCreation
| TargetFileName="*.exe" OR TargetFileName="*.dll" OR TargetFileName="*.ps1" OR TargetFileName="*.vbs" OR TargetFileName="*.js"
| TargetFilePath="C:\\Windows\\Temp\\*" OR TargetFilePath="*\\AppData\\Local\\Temp\\*" OR TargetFilePath="*\\Users\\*\\Downloads\\*" OR TargetFilePath="*\\ProgramData\\*"
| table([@timestamp, ComputerName, UserName, FileName, TargetFileName, TargetFilePath, ImageFileName], limit=100, sortby=@timestamp, order=desc)

7. Renaming of System Utilities to Evade Detection
#event_simpleName=FileRename
| in(SourceFileName, values=["powershell.exe", "cmd.exe", "bitsadmin.exe", "certutil.exe"])
| !in(TargetFileName, values=["powershell.exe", "cmd.exe", "bitsadmin.exe", "certutil.exe"]) // Renamed to something else
| table([@timestamp, ComputerName, UserName, FileName, SourceFileName, TargetFileName, ImageFileName], limit=100, sortby=@timestamp, order=desc)

9. Processes Executing from Compressed Archives
#event_simpleName=ProcessRollup2
| CommandLine="*winrar.exe x *" OR CommandLine="*7z.exe x *" OR CommandLine="*tar -xf *" OR CommandLine="*unzip *"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName]




1. Logs deleted
#event_simpleName=FileDelete
| in(FileName, values=["*.evtx", "*.log", "*.txt"])
| TargetFilePath="*\\Windows\\System32\\winevt\\Logs\\*" OR TargetFilePath="*\\ProgramData\\CrowdStrike\\Logs\\*" OR TargetFilePath="*\\Windows\\Temp\\*"
| table([@timestamp, ComputerName, UserName, FileName, TargetFilePath, ImageFileName, CommandLine], limit=100, sortby=@timestamp, order=desc)

3. B Deleted Event Logs by wevtutil
#event_simpleName=ProcessRollup2
| FileName="wevtutil.exe"
| CommandLine="*clear-log*" OR CommandLine="*cl*"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=100, sortby=@timestamp, order=desc)

5. clear-eventlog (PowerShell)
#event_simpleName=ProcessRollup2
| in(FileName, values=["powershell.exe", "pwsh.exe"])
| CommandLine="*Clear-EventLog*"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=100, sortby=@timestamp, order=desc)

7. Logs modifies
#event_simpleName=RegSystemConfigValueUpdate
| RegObjectName="*\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\*"
| RegValueName="MaxSize" OR RegValueName="Retention"
| table([@timestamp, ComputerName, UserName, FileName, RegObjectName, RegValueName, RegNumericValue, RegStringValue], limit=100, sortby=@timestamp, order=desc)

9. Disabling loggins services
#event_simpleName=ProcessRollup2
| in(FileName, values=["sc.exe", "net.exe"])
| CommandLine="*stop eventlog*" OR CommandLine="*stop wuauserv*" OR CommandLine="*config eventlog start= disabled*"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=100, sortby=@timestamp, order=desc)

11. evtx
#event_simpleName=FileRename
| in(SourceFileName, values=["*.evtx", "*.log"])
| TargetFilePath="*\\Windows\\System32\\winevt\\Logs\\*" OR TargetFilePath="*\\ProgramData\\CrowdStrike\\Logs\\*"
| table([@timestamp, ComputerName, UserName, FileName, SourceFileName, TargetFileName, TargetFilePath, ImageFileName], limit=100, sortby=@timestamp, order=desc)

13. fsutil.exe 
#event_simpleName=ProcessRollup2
| FileName="fsutil.exe"
| CommandLine="*file setzerodata*"
| table([@timestamp, ComputerName, UserName, FileName, CommandLine, ParentBaseFileName], limit=100, sortby=@timestamp, order=desc)

15. Unusual file log activity
#event_simpleName=FileRead
| TargetFilePath="*\\Windows\\System32\\winevt\\Logs\\*" OR TargetFilePath="*\\ProgramData\\CrowdStrike\\Logs\\*"
| !in(FileName, values=["svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "explorer.exe", "powershell.exe", "pwsh.exe", "wevtutil.exe", "logonui.exe"]) // Excluir procesos legítimos
| table([@timestamp, ComputerName, UserName, FileName, TargetFileName, TargetFilePath, ImageFileName, Comm







| groupBy([FileName, ComputerName])
