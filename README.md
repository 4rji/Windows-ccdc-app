# Local Event Notifier (Windows Server 2022 / Domain Controller)

Mini app (WinForms, tray icon) para **notificar con popups** cuando:
- Se crea un usuario (`Security` Event ID **4720**)
- Alguien inicia sesion por RDP (`Security` Event ID **4624** con `LogonType=10`)
- Se emite un ticket Kerberos en el DC (`Security` Event IDs **4768/4769/4770**)

No envia email. Solo notificaciones locales.

## Requisitos
- Windows Server 2022 (DC) con auditoria habilitada para que existan esos eventos.
- Ejecutar la app con permisos suficientes para leer el log **Security** (normalmente **Administrador**).

## Compilar (en el DC o en cualquier Windows con .NET SDK)
1) Instala .NET 8 SDK.
2) En PowerShell:
```powershell
cd LocalEventNotifier
dotnet restore
dotnet publish -c Release -r win-x64 -p:PublishSingleFile=true -p:SelfContained=true
```

El exe queda en:
`LocalEventNotifier\bin\Release\net8.0-windows\win-x64\publish\LocalEventNotifier.exe`

## Probar rapido (sin esperar eventos reales)
```powershell
LocalEventNotifier.exe --selftest
```

## Ejecutar al iniciar sesion (recomendado en vez de UAC manual)
Task Scheduler (Programador de tareas):
1) Create Task
2) Run only when user is logged on (si quieres popups)
3) Run with highest privileges (para leer `Security`)
4) Trigger: At log on
5) Action: Start a program -> `LocalEventNotifier.exe`

## Auditoria (si no ves eventos)
En un DC, lo mas comun es habilitarlo por GPO (Advanced Audit Policy).
Subcategorias tipicas:
- Account Management: User Account Management (para 4720)
- Logon/Logoff: Logon (para 4624)
- Account Logon: Kerberos Authentication Service (para 4768)
- Account Logon: Kerberos Service Ticket Operations (para 4769/4770)

## Configuracion
`settings.json` se copia junto al exe. Puedes apagar alertas si se vuelve muy ruidoso (Kerberos suele generar muchas).
