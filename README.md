# Local Event Notifier (Windows Server 2022 / Domain Controller)

Mini app (WinForms, tray icon) that shows **local pop-up notifications** when:
- A user is created (`Security` Event ID **4720**)
- Someone logs on via RDP (`Security` Event ID **4624** with `LogonType=10`)
- A Kerberos ticket is issued on the DC (`Security` Event IDs **4768/4769/4770**)

No email. Local notifications only.

## Requirements
- Windows Server 2022 (DC) with auditing enabled so these events exist.
- Run the app with enough privileges to read the **Security** log (usually **Administrator**).

## Build (on the DC or any Windows with .NET SDK)
1) Install .NET 8 SDK.
2) In PowerShell:
```powershell
cd LocalEventNotifier
dotnet restore
dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true -p:SelfContained=true
```

The exe will be at:
`LocalEventNotifier\bin\Release\net8.0-windows\win-x64\publish\LocalEventNotifier.exe`

## Build from Linux for Windows (cross-compile)
1) Install .NET 8 SDK on Linux.
2) On Linux:
```bash
cd LocalEventNotifier
dotnet restore
dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true -p:SelfContained=true
```

Files to send to Windows:
- `LocalEventNotifier/bin/Release/net8.0-windows/win-x64/publish/LocalEventNotifier.exe`
- `LocalEventNotifier/bin/Release/net8.0-windows/win-x64/publish/settings.json`

## Quick test (without waiting for real events)
```powershell
LocalEventNotifier.exe --selftest
```

## Investigate the event
- Click the alert to open a window with:
  - Event XML
  - "Open Event Viewer" button
  - "Copy wevtutil" button (exact query by `EventRecordID`)

## Run at logon (recommended vs. manual UAC)
Task Scheduler:
1) Create Task
2) Run only when user is logged on (if you want popups)
3) Run with highest privileges (to read `Security`)
4) Trigger: At log on
5) Action: Start a program -> `LocalEventNotifier.exe`

## Auditing (if you do not see events)
On a DC, the most common approach is enabling it via GPO (Advanced Audit Policy).
Typical subcategories:
- Account Management: User Account Management (for 4720)
- Logon/Logoff: Logon (for 4624)
- Account Logon: Kerberos Authentication Service (for 4768)
- Account Logon: Kerberos Service Ticket Operations (for 4769/4770)

## Configuration
`settings.json` is copied next to the exe. You can disable alerts if it gets too noisy (Kerberos can generate a lot).
