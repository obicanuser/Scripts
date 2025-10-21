import configparser
import uuid

def parse_ini_file(ini_file_path):
    config = configparser.ConfigParser()
    config.read(ini_file_path)
    protections = {}
    if 'Protections' in config:
        for key, value in config['Protections'].items():
            protections[key.lower()] = int(value)
    return protections

def parse_rules_file(rules_file_path):
    config = configparser.ConfigParser()
    config.read(rules_file_path)
    settings = {}
    if 'Settings' in config:
        for key, value in config['Settings'].items():
            settings[key.lower()] = int(value)
    return settings

def generate_hex_conditions(condition_str):
    return ','.join(f'{ord(c):02x},00' for c in condition_str)

def add_rule(f, collection, action, name, desc, user_sid, conditions):
    rule_id = str(uuid.uuid4()).upper()
    f.write(f"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\{collection}\\{ '{{' + rule_id + '}}' }]\n")
    f.write(f"\"Action\"=\"{action}\"\n")
    f.write(f"\"Conditions\"=hex:{conditions}\n")
    f.write(f"\"Description\"=\"{desc}\"\n")
    f.write(f"\"Name\"=\"{name}\"\n")
    f.write(f"\"UserOrGroupSid\"=\"{user_sid}\"\n\n")

def generate_reg_file(ini_protections, rules_settings, output_file):
    with open(output_file, 'w', encoding='utf-16') as f:
        f.write("Windows Registry Editor Version 5.00\n\n")
        
        # Enable Enforcement for Exe, Script, DLL, MSI
        collections = ['Exe', 'Script', 'Dll', 'Msi']
        for col in collections:
            f.write(f"[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\SrpV2\\{col}]\n")
            f.write("\"EnforcementMode\"=dword:00000001\n\n")

        # Global Allow Signed for Exe and DLL (if not blocking untrusted vendors)
        if ini_protections.get('blocksignersnotpresentintrustedvendors', 0) == 0:
            signed_condition = '<Conditions><FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions>'
            add_rule(f, 'Exe', 'Allow', 'Allow Signed Exe', 'Allow all signed executables', 'S-1-1-0', generate_hex_conditions(signed_condition))
            add_rule(f, 'Dll', 'Allow', 'Allow Signed Dll', 'Allow all signed DLLs', 'S-1-1-0', generate_hex_conditions(signed_condition))

        # Allow in Trusted Paths for Exe and DLL (allows unsigned in these paths)
        trusted_paths = [
            ('WINDIR', '%WINDIR%\\*'),
            ('ProgramFiles', '%PROGRAMFILES%\\*'),
            ('ProgramFilesx86', '%PROGRAMFILES(X86)%\\*')
        ]
        for name, path in trusted_paths:
            path_condition = f'<Conditions><FilePathCondition Path="{path}" /></Conditions>'
            add_rule(f, 'Exe', 'Allow', f'Allow Exe {name}', f'Allow executables in {name}', 'S-1-1-0', generate_hex_conditions(path_condition))
            add_rule(f, 'Dll', 'Allow', f'Allow Dll {name}', f'Allow DLLs in {name}', 'S-1-1-0', generate_hex_conditions(path_condition))

        # Deny rules for Exe
        exe_deny_map = {
            'blockprocessesfromusb': ('USB', '%REMOVABLE%\\*', 'Block processes from USB'),
            'blockprocessesfromcdrom': ('CDRom', '%HOT%\\*', 'Block processes from CD-ROM'),
            'blockprocessesfromnetdrive': ('NetDrive', '\\\\*\\*', 'Block processes from net drive'),
            'blockprocessesfromramdisk': ('RamDisk', '%RAMDISK%\\*', 'Block processes from RAM disk'),
            'blockprocessesfromsharedfolder': ('SharedFolder', '%SHAREDFOLDER%\\*', 'Block processes from shared folder'),
            'blockprocessesonmicrosoftvirtualdvdrom': ('VirtualDVD', '%VIRTUALDVD%\\*', 'Block processes from virtual DVD'),
            'blockcmdexeexecution': ('Cmd', '%WINDIR%\\System32\\cmd.exe', 'Block cmd.exe'),
            'blockpowershellexecution': ('PowerShell', '%WINDIR%\\*\\powershell.exe', 'Block powershell.exe'),
            'blockwmicexecution': ('Wmic', '%WINDIR%\\System32\\wmic.exe', 'Block wmic.exe'),
            'blockbitsadminexecution': ('Bitsadmin', '%WINDIR%\\System32\\bitsadmin.exe', 'Block bitsadmin.exe'),
            'blocknetshexecution': ('Netsh', '%WINDIR%\\System32\\netsh.exe', 'Block netsh.exe'),
            'blockregexecution': ('Reg', '%WINDIR%\\reg.exe', 'Block reg.exe'),
            'blockxcopyexecution': ('Xcopy', '%WINDIR%\\System32\\xcopy.exe', 'Block xcopy.exe'),
            'blockdiskpartexecution': ('Diskpart', '%WINDIR%\\System32\\diskpart.exe', 'Block diskpart.exe'),
            'blockformatcomexecution': ('Format', '%WINDIR%\\System32\\format.com', 'Block format.com'),
            'blocktasklistexecution': ('Tasklist', '%WINDIR%\\System32\\tasklist.exe', 'Block tasklist.exe'),
            'blocksysteminfoexecution': ('Systeminfo', '%WINDIR%\\System32\\systeminfo.exe', 'Block systeminfo.exe'),
            'blockwhoamiexecution': ('Whoami', '%WINDIR%\\System32\\whoami.exe', 'Block whoami.exe'),
            'blockvssadminexecution': ('Vssadmin', '%WINDIR%\\System32\\vssadmin.exe', 'Block vssadmin.exe'),
            'blockschtasksexe': ('Schtasks', '%WINDIR%\\System32\\schtasks.exe', 'Block schtasks.exe'),
            'blockcurlexecution': ('Curl', '%WINDIR%\\System32\\curl.exe', 'Block curl.exe'),
            'blockftptftptelnetexecution': ('Ftp', '%WINDIR%\\System32\\ftp.exe', 'Block ftp.exe'),
            'blockjavaexecution': ('Java', 'java.exe', 'Block java.exe'),
            'blockprocessesfromjava': ('JavaProcesses', '*java*.exe', 'Block processes from Java'),
            'blockprocessesfromjavawexceptjava': ('Javaw', 'javaw.exe', 'Block javaw.exe except java'),
            'blockprocessesreatedtopython': ('Python', 'python.exe', 'Block Python processes'),
            'blockexecutionofwgetexe': ('Wget', 'wget.exe', 'Block wget.exe'),
            'blockiexploreexecution': ('Iexplore', '%PROGRAMFILES%\\Internet Explorer\\iexplore.exe', 'Block iexplore.exe'),
            'blockmicrosoftpdfreaderexecution': ('PdfReader', '%PROGRAMFILES%\\WindowsApps\\Microsoft.MicrosoftEdgePDF*\\MicrosoftPdfReader.exe', 'Block Microsoft PDF reader'),
            'blockwingetapp': ('Winget', '%WINDIR%\\System32\\winget.exe', 'Block winget.exe'),
            'blockcortanaexecution': ('Cortana', '%WINDIR%\\SystemApps\\Microsoft.Windows.Cortana*\\cortana.exe', 'Block Cortana'),
            'blocksyskeyexe': ('Syskey', '%WINDIR%\\System32\\syskey.exe', 'Block syskey.exe'),
            'blockshutdowexeexecution': ('Shutdown', '%WINDIR%\\System32\\shutdown.exe', 'Block shutdown.exe'),
            'blockatexecution': ('At', '%WINDIR%\\System32\\at.exe', 'Block at.exe'),
            'blockreginiexecution': ('Regini', '%WINDIR%\\System32\\regini.exe', 'Block regini.exe'),
            'blocktaskkillexecution': ('Taskkill', '%WINDIR%\\System32\\taskkill.exe', 'Block taskkill.exe'),
            'blockcaclsicaclsexecution': ('Cacls', '%WINDIR%\\System32\\cacls.exe', 'Block cacls/icacls.exe'),
            'blocktakeownexecution': ('Takeown', '%WINDIR%\\System32\\takeown.exe', 'Block takeown.exe'),
            'blocksc execution': ('Sc', '%WINDIR%\\System32\\sc.exe', 'Block sc.exe'),
            'blocknetnet1execution': ('Net', '%WINDIR%\\System32\\net.exe', 'Block net/net1.exe'),
            'blockwscriptcscriptexecution': ('Wscript', '%WINDIR%\\System32\\wscript.exe', 'Block wscript/cscript.exe'),
            'blocknslookupexecution': ('Nslookup', '%WINDIR%\\System32\\nslookup.exe', 'Block nslookup.exe'),
            'blockscpsshsftpexecution': ('Ssh', '%WINDIR%\\System32\\OpenSSH\\ssh.exe', 'Block scp/ssh/sftp.exe'),
            'blockprocessesfrommmc': ('Mmc', '%WINDIR%\\System32\\mmc.exe', 'Block processes from MMC'),
            'blockprocessesfromwmiprvse': ('Wmiprvse', '%WINDIR%\\System32\\wbem\\wmiprvse.exe', 'Block processes from wmiprvse'),
            'blockprocessesfrommstsc': ('Mstsc', '%WINDIR%\\System32\\mstsc.exe', 'Block processes from mstsc'),
            'blockprocessesfromruntimebroker': ('RuntimeBroker', '%WINDIR%\\System32\\runtimebroker.exe', 'Block processes from runtimebroker'),
            'blockprocessesfromwscript': ('Wscript', '%WINDIR%\\System32\\wscript.exe', 'Block processes from wscript'),
            'blockprocessesfrommshta': ('Mshta', '%WINDIR%\\System32\\mshta.exe', 'Block processes from mshta'),
            'blockprocessesfromwmic': ('WmicParent', '%WINDIR%\\System32\\wmic.exe', 'Block processes from WMIC'),
            'blockaddinu tilexecution': ('AddInUtil', '%WINDIR%\\System32\\addinutil.exe', 'Block AddInUtil.exe'),
            'blockaddinprocessexecution': ('AddInProcess', '%PROGRAMFILES%\\WindowsApps\\*AddInProcess.exe', 'Block AddInProcess.exe'),
            'blockcsharpcompilecsc': ('CSC', '%WINDIR%\\Microsoft.NET\\Framework*\\csc.exe', 'Block C# compiler csc.exe'),
            'blockcvtres exe': ('CVTres', '%WINDIR%\\Microsoft.NET\\Framework*\\cvtres.exe', 'Block CVTres.exe'),
            'blockvisualbasiccompilervbc': ('VBC', '%WINDIR%\\Microsoft.NET\\Framework*\\vbc.exe', 'Block VB compiler vbc.exe'),
            'blockdnxexecution': ('Dnx', '*dnx.exe', 'Block Dnx.exe'),
            'blockwindowsdebuggingtools': ('DebugTools', '%PROGRAMFILES%\\Windows Kits\\*\\Debuggers\\*', 'Block Windows debugging tools'),
            'blockprocessesreatedtonirsofer': ('NirSofer', '*nirsoft*.exe', 'Block NirSofer tools'),
            'blockprocessesreatedtosecurityxploded': ('SecurityXploded', '*securityxploded*.exe', 'Block SecurityXploded tools'),
            'blockprocessesreatedtojernejsimon': ('JernejSimon', '*jernejsimon*.exe', 'Block Jernej Simon tools'),
            'blockremotedesktopaccesstools': ('RDP', '%WINDIR%\\System32\\mstsc.exe', 'Block remote desktop tools'),
            'blocksysinternals pstools': ('PsTools', '*psexec*.exe', 'Block Sysinternals PsTools'),
            'blockprocessesonnetframeworkfolder': ('NetFramework', '%WINDIR%\\Microsoft.NET\\*\\*.exe', 'Block processes in NET framework folder'),
            'blockprocessesonrootfolders': ('RootFolders', '*:\\*', 'Block processes on root folders'),
            'blockprocessesonpublicfolder': ('PublicFolder', '%PUBLIC%\\*', 'Block processes on public folder'),
            'blockprocessesondocuments': ('Documents', '%USERPROFILE%\\Documents\\*', 'Block processes on documents'),
            'blockprocessesonallusersfolder': ('AllUsers', '%ALLUSERSPROFILE%\\*', 'Block processes on all users folder'),
            'blockanyprocessexecutedfromwebbrowsers': ('WebBrowsers', '*browser*.exe', 'Block processes from web browsers'),
            'blockprocessesfromvirtualboxvmexe': ('VirtualBox', '*VBox*.exe', 'Block processes from VirtualBox'),
            'blockprocessesfromvmwarevmxexe': ('VMware', '*vmware*.exe', 'Block processes from VMware'),
            'block16bitprocesses': ('16Bit', '*.com', 'Block 16-bit processes'),
            'blockiexploreexecution': ('IExplore', '%PROGRAMFILES%\\Internet Explorer\\iexplore.exe', 'Block Internet Explorer'),
            'blockmsedgeexecution': ('MsEdge', '%PROGRAMFILES(X86)%\\Microsoft\\Edge\\Application\\msedge.exe', 'Block Microsoft Edge'),
            'blockwindowsstoreappexecution': ('WindowsStore', '%PROGRAMFILES%\\WindowsApps\\*.exe', 'Block Windows Store apps'),
            'blockwindowsterminalapp': ('WindowsTerminal', '%LOCALAPPDATA%\\Microsoft\\WindowsApps\\wt.exe', 'Block Windows Terminal'),
            'blocklxrunexecution': ('LxRun', '%WINDIR%\\System32\\lxrun.exe', 'Block LxRun.exe'),
            'blockbashexecution': ('Bash', '%WINDIR%\\System32\\bash.exe', 'Block bash.exe'),
            'blocksdbinstexecution': ('Sdbinst', '%WINDIR%\\System32\\sdbinst.exe', 'Block sdbinst.exe'),
            'blockmakecabexecution': ('Makecab', '%WINDIR%\\System32\\makecab.exe', 'Block makecab.exe'),
            'blocklogoffexecution': ('Logoff', '%WINDIR%\\System32\\logoff.exe', 'Block logoff.exe'),
            'blocksubinaclexecution': ('SubInACL', '*SubInACL.exe', 'Block SubInACL.exe'),
            'blockprocessesreatedtojernejsimon': ('JernejSimon', '*simoncic*.exe', 'Block Jernej Simon tools'),
            'blockprocessesfrommmc': ('MMC', '%WINDIR%\\System32\\mmc.exe', 'Block MMC'),
            'blockregeditexecution': ('Regedit', '%WINDIR%\\regedit.exe', 'Block regedit.exe'),
            'blockwindows servicesmanager execution': ('Services', '%WINDIR%\\System32\\services.msc', 'Block services.msc'),
            'blockeventvwr execution': ('Eventvwr', '%WINDIR%\\System32\\eventvwr.exe', 'Block eventvwr.exe'),
            'blocktaskschd execution': ('Taskschd', '%WINDIR%\\System32\\taskmgr.exe', 'Block taskschd.msc'),
            'blockmicrosoftmanagementconsoleexecution': ('MMC', '%WINDIR%\\System32\\mmc.exe', 'Block MMC'),
            'blockgrouppolicyeditorexecution': ('Gpedit', '%WINDIR%\\System32\\gpedit.msc', 'Block gpedit.msc'),
            'blockmsconfigexecution': ('Msconfig', '%WINDIR%\\System32\\msconfig.exe', 'Block msconfig.exe'),
            'blockwindowsfeaturesdialogexecution': ('OptionalFeatures', '%WINDIR%\\System32\\OptionalFeatures.exe', 'Block optional features dialog'),
            'blockuaccontrolsettingsexecution': ('UAC', '*uac*.exe', 'Block UAC settings'),
            'blockwindowsfirewalldialogexecution': ('Firewall', '%WINDIR%\\System32\\firewall.cpl', 'Block firewall dialog'),
            'blocksystemrestoredialogexecution': ('SystemRestore', '%WINDIR%\\System32\\rstrui.exe', 'Block system restore dialog'),
            'blockquickassistexecution': ('QuickAssist', '%PROGRAMFILES%\\WindowsApps\\*QuickAssist.exe', 'Block quick assist'),
            'blocksystemsettingsexecution': ('SystemSettings', '%WINDIR%\\ImmersiveControlPanel\\SystemSettings.exe', 'Block system settings'),
            'blockwindowssecurityuiexecution': ('SecurityUI', '%WINDIR%\\System32\\wscui.cpl', 'Block Windows security UI'),
            'blockmsinfo32execution': ('Msinfo32', '%WINDIR%\\System32\\msinfo32.exe', 'Block msinfo32.exe'),
            'blockdxdiagexecution': ('Dxdiag', '%WINDIR%\\System32\\dxdiag.exe', 'Block dxdiag.exe'),
            'blockwindowsmediaplayerexecution': ('MediaPlayer', '%PROGRAMFILES%\\Windows Media Player\\wmplayer.exe', 'Block Windows Media Player'),
            'blockmicrosoftdiagnostictoolexecution': ('MSDT', '%WINDIR%\\System32\\msdt.exe', 'Block MSDT.exe'),
            'blockprocessesonrootfolders': ('Root', '?:\\*.exe', 'Block processes on root folders')
        }

        for key, (name, path, desc) in exe_deny_map.items():
            if ini_protections.get(key, 0) == 1:
                condition = f'<Conditions><FilePathCondition Path="{path}" /></Conditions>'
                add_rule(f, 'Exe', 'Deny', f'Deny {name}', desc, 'S-1-1-0', generate_hex_conditions(condition))

        # For unsigned locations, implicit deny is used, so no explicit deny needed to avoid blocking signed

        # Script Deny rules
        script_deny_map = {
            'blockcmdscripts': ('CMD', '*.cmd', 'Block CMD scripts'),
            'blockps1scripts': ('PS1', '*.ps1', 'Block PS1 scripts'),
            'blockjarscripts': ('JAR', '*.jar', 'Block JAR scripts'),
            'blockmscscripts': ('MSC', '*.msc', 'Block MSC scripts'),
            'blockbatscripts': ('BAT', '*.bat', 'Block BAT scripts'),
            'blockregscripts': ('REG', '*.reg', 'Block REG scripts'),
            'blockmspscripts': ('MSP', '*.msp', 'Block MSP scripts'),
            'blockmsuscripts': ('MSU', '*.msu', 'Block MSU scripts'),
            'blockmhtmlscripts': ('MHTML', '*.mhtml', 'Block MHTML scripts'),
            'blocknfoscripts': ('NFO', '*.nfo', 'Block NFO scripts'),
            'blockchmscripts': ('CHM', '*.chm', 'Block CHM scripts'),
            'blockhlpscripts': ('HLP', '*.hlp', 'Block HLP scripts'),
            'blockjsscripts': ('JS', '*.js', 'Block JS scripts'),
            'blockmscscriptoutsidesystemfolder': ('MSCOutside', '*.msc', 'Block MSC outside system'),
            'blocksuspiciousscripts': ('SuspScripts', '*.vbs', 'Block suspicious scripts'),
            'blockmsrcincidentscripts': ('MsrcIncident', '*.xml', 'Block MSRC incident scripts')
        }

        for key, (name, path, desc) in script_deny_map.items():
            if ini_protections.get(key, 0) == 1:
                condition = f'<Conditions><FilePathCondition Path="{path}" /></Conditions>'
                add_rule(f, 'Script', 'Deny', f'Deny {name}', desc, 'S-1-1-0', generate_hex_conditions(condition))

        # DLL Deny rules for loading blocks
        dll_deny_map = {
            'blockrundll32fromloadingdllsinuserspace': ('RundllUserSpace', '%USERPROFILE%\\*.dll', 'Block rundll32 loading DLLs in user space'),
            'blockregsvr32fromloadingdllsinuserspace': ('RegsvrUserSpace', '%USERPROFILE%\\*.dll', 'Block regsvr32 loading DLLs in user space'),
            'blockrundll32fromloadingdllsonsmbshare': ('RundllSMB', '\\\\*\\*.dll', 'Block rundll32 loading DLLs on SMB share'),
            'blockrundll32fromloadingcomserverpayload': ('RundllCOM', '*comserver*.dll', 'Block rundll32 loading COM server'),
            'blockregsvcsloadingdlls': ('Regsvcs', '*regsvcs*.dll', 'Block regsvcs loading DLLs'),
            'blockregasmloadingdlls': ('Regasm', '*regasm*.dll', 'Block regasm loading DLLs'),
            'preventinstallutilloadingdlls': ('InstallUtil', '*installutil*.dll', 'Block installutil loading DLLs'),
            'preventrundll32control_rundll': ('RundllControl', '*rundll*.dll', 'Block rundll32 Control_RunDLL'),
            'preventregsvr32loadingdlls': ('Regsvr', '*.dll', 'Block regsvr32 loading DLLs'),
            'blockparticularprocessespreventdllsideload': ('DLLSideload', '*sideload*.dll', 'Block DLL sideload')
        }

        for key, (name, path, desc) in dll_deny_map.items():
            if ini_protections.get(key, 0) == 1:
                condition = f'<Conditions><FilePathCondition Path="{path}" /></Conditions>'
                add_rule(f, 'Dll', 'Deny', f'Deny {name}', desc, 'S-1-1-0', generate_hex_conditions(condition))

        # MSI Deny rules
        msi_deny_map = {
            'blockmsiexecloadingmsi': ('Msiexec', '*.msi', 'Block msiexec loading MSI'),
            'blockexecutionmsiunsigned': ('MsiUnsigned', '*.msi', 'Block unsigned MSI execution')
        }

        for key, (name, path, desc) in msi_deny_map.items():
            if ini_protections.get(key, 0) == 1:
                condition = f'<Conditions><FilePathCondition Path="{path}" /></Conditions>'
                add_rule(f, 'Msi', 'Deny', f'Deny {name}', desc, 'S-1-1-0', generate_hex_conditions(condition))

def main():
    ini_file = "1.ini"
    rules_file = "OSArmor.rules"
    output_reg = "osarmor_rules.reg"
    
    ini_protections = parse_ini_file(ini_file)
    rules_settings = parse_rules_file(rules_file)
    generate_reg_file(ini_protections, rules_settings, output_reg)
    print(f"Registry file '{output_reg}' generated successfully.")

if __name__ == "__main__":
    main()