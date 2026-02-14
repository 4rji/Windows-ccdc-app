using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Drawing;
using System.Text.Json;
using System.Xml.Linq;

namespace LocalEventNotifier;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new TrayAppContext(args));
    }
}

internal sealed class TrayAppContext : ApplicationContext
{
    private readonly NotifyIcon _notifyIcon;
    private readonly Control _ui;
    private readonly List<EventLogWatcher> _watchers = new();
    private readonly AppSettings _settings;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recent = new();
    private int _cleanupEveryN;

    private bool _started;

    public TrayAppContext(string[] args)
    {
        _settings = AppSettings.Load();

        _ui = new Control();
        _ui.CreateControl();

        _notifyIcon = new NotifyIcon
        {
            Visible = true,
            Icon = SystemIcons.Shield,
            Text = "Local Event Notifier",
            ContextMenuStrip = BuildMenu()
        };

        var selfTest = args.Any(a => string.Equals(a, "--selftest", StringComparison.OrdinalIgnoreCase));
        if (selfTest)
        {
            StartSelfTest(exitWhenDone: true);
            return;
        }

        // Start watchers only after the WinForms message loop is live.
        var timer = new System.Windows.Forms.Timer { Interval = 1000 };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            timer.Dispose();
            StartWatchers();
        };
        timer.Start();
    }

    private ContextMenuStrip BuildMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Self-test", null, (_, _) => StartSelfTest(exitWhenDone: false));
        menu.Items.Add("Salir", null, (_, _) => ExitThread());
        return menu;
    }

    private void StartSelfTest(bool exitWhenDone)
    {
        var timer = new System.Windows.Forms.Timer { Interval = 800 };
        var step = 0;
        timer.Tick += (_, _) =>
        {
            step++;
            switch (step)
            {
                case 1:
                    Show("Self-test", "Esta es una notificacion de prueba.");
                    break;
                case 2:
                    Show("Usuario creado (4720)", "Usuario: testuser\nCreado por: admin\nHora: (self-test)");
                    break;
                case 3:
                    Show("RDP logon (4624 tipo 10)", "Usuario: DOMAIN\\alice\nIP: 10.0.0.5\nHora: (self-test)");
                    break;
                case 4:
                    Show("Kerberos ticket (4769)", "Usuario: DOMAIN\\alice\nService: cifs/fileserver\nIP: 10.0.0.5\nHora: (self-test)");
                    break;
                default:
                    timer.Stop();
                    timer.Dispose();
                    if (exitWhenDone)
                    {
                        ExitThread();
                    }
                    break;
            }
        };
        timer.Start();
    }

    private void StartWatchers()
    {
        if (_started) return;
        _started = true;

        if (_settings.EnableUserCreated)
        {
            Watch(
                logName: "Security",
                xPath: "*[System[(EventID=4720)]]",
                onEvent: e => NotifyUserCreated(e));
        }

        if (_settings.EnableRdpLogon)
        {
            Watch(
                logName: "Security",
                xPath: "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]",
                onEvent: e => NotifyRdpLogon(e));
        }

        if (_settings.EnableKerberosTickets)
        {
            // NOTE: On a DC this can be very noisy.
            Watch(
                logName: "Security",
                xPath: "*[System[(EventID=4768 or EventID=4769 or EventID=4770)]]",
                onEvent: e => NotifyKerberos(e));
        }

        Show("Local Event Notifier", "Escuchando eventos del log Security...");
    }

    private void Watch(string logName, string xPath, Action<EventSnapshot> onEvent)
    {
        try
        {
            var query = new EventLogQuery(logName, PathType.LogName, xPath);
            var watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += (_, args) =>
            {
                if (args.EventException is not null)
                {
                    Post(() => Show("Error leyendo Event Log", args.EventException.Message, ToolTipIcon.Error));
                    return;
                }

                if (args.EventRecord is null) return;

                EventSnapshot snap;
                try
                {
                    snap = EventSnapshot.From(args.EventRecord);
                }
                catch (Exception ex)
                {
                    Post(() => Show("Error parseando evento", ex.Message, ToolTipIcon.Error));
                    return;
                }
                finally
                {
                    args.EventRecord.Dispose();
                }

                try
                {
                    onEvent(snap);
                }
                catch (Exception ex)
                {
                    Post(() => Show("Error procesando evento", ex.Message, ToolTipIcon.Error));
                }
            };

            watcher.Enabled = true;
            _watchers.Add(watcher);
        }
        catch (Exception ex)
        {
            Show("No se pudo abrir el log Security", ex.Message, ToolTipIcon.Error);
        }
    }

    private void NotifyUserCreated(EventSnapshot e)
    {
        var d = e.Data;
        var createdUser = JoinDomainUser(
            d.GetAny("TargetDomainName", "SamAccountDomain"),
            d.GetAny("TargetUserName", "SamAccountName", "AccountName"));
        var byUser = JoinDomainUser(d.GetAny("SubjectDomainName"), d.GetAny("SubjectUserName"));

        if (ShouldDedup($"4720|{createdUser}|{byUser}")) return;

        var msg = $"Usuario: {createdUser}\nCreado por: {byUser}\nHora: {FmtTime(e.TimeCreated)}";
        Post(() => Show("Usuario creado (4720)", msg));
    }

    private void NotifyRdpLogon(EventSnapshot e)
    {
        var d = e.Data;
        var user = JoinDomainUser(d.GetAny("TargetDomainName"), d.GetAny("TargetUserName"));
        var ip = d.GetAny("IpAddress") ?? d.GetAny("WorkstationName") ?? "(n/a)";

        if (ShouldDedup($"4624|{user}|{ip}")) return;

        var msg = $"Usuario: {user}\nIP/Host: {ip}\nHora: {FmtTime(e.TimeCreated)}";
        Post(() => Show("RDP logon (4624 tipo 10)", msg));
    }

    private void NotifyKerberos(EventSnapshot e)
    {
        var d = e.Data;

        var user = JoinDomainUser(
            d.GetAny("TargetDomainName", "RealmName"),
            d.GetAny("TargetUserName", "AccountName"));

        if (_settings.IgnoreMachineAccounts && user.EndsWith("$", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var ip = d.GetAny("IpAddress") ?? "(n/a)";
        var svc = d.GetAny("ServiceName") ?? "(n/a)";

        var key = $"{e.EventId}|{user}|{ip}|{svc}";
        if (ShouldDedup(key)) return;

        var title = e.EventId switch
        {
            4768 => "Kerberos TGT (4768)",
            4769 => "Kerberos Service Ticket (4769)",
            4770 => "Kerberos ticket renovado (4770)",
            _ => $"Kerberos ({e.EventId})"
        };

        var msg = $"Usuario: {user}\nService: {svc}\nIP: {ip}\nHora: {FmtTime(e.TimeCreated)}";
        Post(() => Show(title, msg));
    }

    private bool ShouldDedup(string key)
    {
        var now = DateTimeOffset.UtcNow;
        var window = TimeSpan.FromSeconds(Math.Max(0, _settings.DedupSeconds));
        if (window == TimeSpan.Zero) return false;

        if (_recent.TryGetValue(key, out var last) && (now - last) < window)
        {
            return true;
        }

        _recent[key] = now;

        // Best-effort cleanup to keep memory bounded (avoid scanning on every event).
        if (Interlocked.Increment(ref _cleanupEveryN) % 200 == 0)
        {
            foreach (var kvp in _recent)
            {
                if ((now - kvp.Value) > window + window)
                {
                    _recent.TryRemove(kvp.Key, out _);
                }
            }
        }

        return false;
    }

    private void Post(Action action)
    {
        try
        {
            _ui.BeginInvoke(action);
        }
        catch
        {
            // If the UI is already shutting down, ignore.
        }
    }

    private void Show(string title, string text, ToolTipIcon icon = ToolTipIcon.Info)
    {
        _notifyIcon.ShowBalloonTip(6000, title, text, icon);
    }

    protected override void ExitThreadCore()
    {
        foreach (var w in _watchers)
        {
            try { w.Enabled = false; } catch { }
            try { w.Dispose(); } catch { }
        }

        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _ui.Dispose();

        base.ExitThreadCore();
    }

    private static string FmtTime(DateTime? dt)
        => dt is null ? "(n/a)" : dt.Value.ToString("yyyy-MM-dd HH:mm:ss");

    private static string JoinDomainUser(string? domain, string? user)
    {
        domain = string.IsNullOrWhiteSpace(domain) ? null : domain.Trim();
        user = string.IsNullOrWhiteSpace(user) ? null : user.Trim();
        if (domain is null && user is null) return "(n/a)";
        if (domain is null) return user!;
        if (user is null) return domain;
        return $"{domain}\\{user}";
    }
}

internal sealed record AppSettings(
    bool EnableUserCreated = true,
    bool EnableRdpLogon = true,
    bool EnableKerberosTickets = true,
    bool IgnoreMachineAccounts = true,
    int DedupSeconds = 10)
{
    public static AppSettings Load()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "settings.json");
            if (!File.Exists(path)) return new AppSettings();

            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<AppSettings>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            }) ?? new AppSettings();
        }
        catch
        {
            return new AppSettings();
        }
    }
}

internal sealed record EventSnapshot(
    int EventId,
    DateTime? TimeCreated,
    IReadOnlyDictionary<string, string> Data)
{
    public static EventSnapshot From(EventRecord r)
    {
        // Only keep what we need; EventRecord must be disposed by the caller.
        var xml = r.ToXml();
        var data = ParseEventData(xml);
        return new EventSnapshot(r.Id, r.TimeCreated, data);
    }

    private static IReadOnlyDictionary<string, string> ParseEventData(string xml)
    {
        var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var doc = XDocument.Parse(xml);
        foreach (var el in doc.Descendants().Where(e => e.Name.LocalName == "Data"))
        {
            var name = el.Attribute("Name")?.Value;
            if (string.IsNullOrWhiteSpace(name)) continue;
            dict[name] = el.Value;
        }

        return dict;
    }
}

internal static class DictExt
{
    public static string? GetAny(this IReadOnlyDictionary<string, string> dict, params string[] keys)
    {
        foreach (var k in keys)
        {
            if (dict.TryGetValue(k, out var v) && !string.IsNullOrWhiteSpace(v))
            {
                return v;
            }
        }
        return null;
    }
}
