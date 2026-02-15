using System.Collections.Concurrent;
using System.Diagnostics;
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
    private readonly FileLog? _fileLog;
    private readonly TimelineCsvLog? _timelineCsvLog;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recent = new();
    private readonly ConcurrentQueue<PendingNotification> _notificationQueue = new();
    private int _cleanupEveryN;

    private bool _started;
    private EventSnapshot? _lastEvent;
    private EventDetailsForm? _detailsForm;

    private int _unreadEvents;
    private bool _balloonInFlight;
    private DateTimeOffset _balloonAssumeClosedAtUtc;

    public TrayAppContext(string[] args)
    {
        _settings = AppSettings.Load();
        _fileLog = FileLog.TryCreate(_settings);
        _timelineCsvLog = TimelineCsvLog.TryCreate(_settings);

        _ui = new Control();
        _ui.CreateControl();

        _notifyIcon = new NotifyIcon
        {
            Visible = true,
            Icon = SystemIcons.Shield,
            Text = "Local Event Notifier",
            ContextMenuStrip = BuildMenu()
        };
        _notifyIcon.BalloonTipClicked += (_, _) => OpenLastEventDetails();
        _notifyIcon.BalloonTipClosed += (_, _) =>
        {
            // Windows can drop or coalesce balloon tips; treat the closure as a signal to show the next one.
            _balloonInFlight = false;
            PumpNotifications();
        };

        // Periodically pump the queue (also acts as a failsafe if BalloonTipClosed doesn't fire).
        var pumpTimer = new System.Windows.Forms.Timer { Interval = 250 };
        pumpTimer.Tick += (_, _) => PumpNotifications();
        pumpTimer.Start();

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
        menu.Items.Add("View last event", null, (_, _) => OpenLastEventDetails());
        menu.Items.Add("Open log file", null, (_, _) => OpenLogFile());
        menu.Items.Add("Open log folder", null, (_, _) => OpenLogFolder());
        menu.Items.Add("Open timeline CSV", null, (_, _) => OpenTimelineCsv());
        menu.Items.Add("Open timeline folder", null, (_, _) => OpenTimelineFolder());
        menu.Items.Add("Exit", null, (_, _) => ExitThread());
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
                    Show("Self-test", "This is a test notification.");
                    break;
                case 2:
                    Show("User created (4720)", "User: testuser\nCreated by: admin\nTime: (self-test)");
                    break;
                case 3:
                    Show("RDP logon (4624 type 10)", "User: DOMAIN\\alice\nIP: 10.0.0.5\nTime: (self-test)");
                    break;
                case 4:
                    Show("Kerberos ticket (4769)", "User: DOMAIN\\alice\nService: cifs/fileserver\nIP: 10.0.0.5\nTime: (self-test)");
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

        Show("Local Event Notifier", "Watching events in the Security log...");
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
                    Post(() => Show("Error reading Event Log", args.EventException.Message, ToolTipIcon.Error));
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
                    Post(() => Show("Error parsing event", ex.Message, ToolTipIcon.Error));
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
                    Post(() => Show("Error handling event", ex.Message, ToolTipIcon.Error));
                }
            };

            watcher.Enabled = true;
            _watchers.Add(watcher);
        }
        catch (Exception ex)
        {
            Show("Could not open the Security log", ex.Message, ToolTipIcon.Error);
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

        var msg = $"User: {createdUser}\nCreated by: {byUser}\nTime: {FmtTime(e.TimeCreated)}";
        Post(() => ShowEvent("User created (4720)", msg, e));
    }

    private void NotifyRdpLogon(EventSnapshot e)
    {
        var d = e.Data;
        var user = JoinDomainUser(d.GetAny("TargetDomainName"), d.GetAny("TargetUserName"));
        var ip = d.GetAny("IpAddress") ?? d.GetAny("WorkstationName") ?? "(n/a)";

        if (ShouldDedup($"4624|{user}|{ip}")) return;

        var msg = $"User: {user}\nIP/Host: {ip}\nTime: {FmtTime(e.TimeCreated)}";
        Post(() => ShowEvent("RDP logon (4624 type 10)", msg, e));
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
            4770 => "Kerberos ticket renewed (4770)",
            _ => $"Kerberos ({e.EventId})"
        };

        var msg = $"User: {user}\nService: {svc}\nIP: {ip}\nTime: {FmtTime(e.TimeCreated)}";
        Post(() => ShowEvent(title, msg, e));
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
        if (icon == ToolTipIcon.Error)
        {
            _fileLog?.LogError(title, text);
            _timelineCsvLog?.LogError(title, text);
        }

        EnqueueNotification(new PendingNotification(
            Title: title,
            Text: text,
            Icon: icon,
            TimeoutMs: Math.Max(1000, _settings.NotificationTimeoutMs),
            CountsAsUnreadEvent: false));
    }

    private void ShowEvent(string title, string text, EventSnapshot e, ToolTipIcon icon = ToolTipIcon.Info)
    {
        _lastEvent = e;
        _fileLog?.LogEvent(e, title, text, icon);
        _timelineCsvLog?.LogEvent(e, title, text, icon);
        var hint = _settings.AppendClickHint ? "\n\nClick to view details." : "";
        EnqueueNotification(new PendingNotification(
            Title: title,
            Text: text + hint,
            Icon: icon,
            TimeoutMs: Math.Max(1000, _settings.NotificationTimeoutMs),
            CountsAsUnreadEvent: true));
    }

    private void EnqueueNotification(PendingNotification n)
    {
        _notificationQueue.Enqueue(n);
        PumpNotifications();
    }

    private void PumpNotifications()
    {
        // Always run from the UI thread.
        if (_ui.InvokeRequired)
        {
            Post(PumpNotifications);
            return;
        }

        // If a balloon is "in flight", release it after a timeout so the queue doesn't stall.
        if (_balloonInFlight && DateTimeOffset.UtcNow < _balloonAssumeClosedAtUtc)
        {
            return;
        }

        _balloonInFlight = false;

        if (!_notificationQueue.TryDequeue(out var n))
        {
            return;
        }

        if (n.CountsAsUnreadEvent)
        {
            _unreadEvents++;
            UpdateTrayTooltip();
        }

        _balloonInFlight = true;
        _balloonAssumeClosedAtUtc = DateTimeOffset.UtcNow.AddMilliseconds(n.TimeoutMs + 1500);

        try
        {
            _notifyIcon.ShowBalloonTip(n.TimeoutMs, n.Title, n.Text, n.Icon);
        }
        catch
        {
            // Best-effort: if the shell refuses the balloon, keep pumping subsequent notifications.
            _balloonInFlight = false;
        }
    }

    private void UpdateTrayTooltip()
    {
        // NotifyIcon.Text has a small max length (63 chars). Keep it short.
        var baseText = "Local Event Notifier";
        var text = _unreadEvents > 0 ? $"{baseText} ({_unreadEvents} new)" : baseText;
        if (text.Length > 63) text = text[..63];

        try { _notifyIcon.Text = text; } catch { }
    }

    private void OpenLastEventDetails()
    {
        Post(() =>
        {
            if (_lastEvent is null)
            {
                Show("Local Event Notifier", "No recent event to show.");
                return;
            }

            if (_detailsForm is null || _detailsForm.IsDisposed)
            {
                _detailsForm = new EventDetailsForm();
            }

            _detailsForm.SetSnapshot(_lastEvent);
            _detailsForm.Show();
            _detailsForm.Activate();

            _unreadEvents = 0;
            UpdateTrayTooltip();
        });
    }

    protected override void ExitThreadCore()
    {
        foreach (var w in _watchers)
        {
            try { w.Enabled = false; } catch { }
            try { w.Dispose(); } catch { }
        }

        try { _fileLog?.Dispose(); } catch { }
        try { _timelineCsvLog?.Dispose(); } catch { }

        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _ui.Dispose();

        base.ExitThreadCore();
    }

    private void OpenTimelineCsv()
    {
        if (_timelineCsvLog is null)
        {
            Show("Local Event Notifier", "Timeline CSV logging is disabled.");
            return;
        }

        _timelineCsvLog.OpenCsvFile();
        Show("Local Event Notifier", $"Timeline CSV:\n{_timelineCsvLog.PathOnDisk}");
    }

    private void OpenTimelineFolder()
    {
        if (_timelineCsvLog is null)
        {
            Show("Local Event Notifier", "Timeline CSV logging is disabled.");
            return;
        }

        _timelineCsvLog.OpenFolder();
        Show("Local Event Notifier", $"Timeline folder:\n{_timelineCsvLog.DirectoryOnDisk}");
    }

    private void OpenLogFile()
    {
        if (_fileLog is null)
        {
            Show("Local Event Notifier", "File logging is disabled.");
            return;
        }

        _fileLog.OpenLogFile();
        Show("Local Event Notifier", $"Log file:\n{_fileLog.PathOnDisk}");
    }

    private void OpenLogFolder()
    {
        if (_fileLog is null)
        {
            Show("Local Event Notifier", "File logging is disabled.");
            return;
        }

        _fileLog.OpenLogFolder();
        Show("Local Event Notifier", $"Log folder:\n{_fileLog.DirectoryOnDisk}");
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
    int DedupSeconds = 10,
    bool AppendClickHint = true,
    int NotificationTimeoutMs = 8000,
    bool EnableFileLog = true,
    string? LogPath = null,
    int LogMaxBytes = 2_000_000,
    int LogMaxFiles = 5,
    bool LogIncludeXml = false,
    bool EnableTimelineCsvLog = true,
    string? TimelineCsvPath = null,
    int TimelineCsvMaxBytes = 2_000_000,
    int TimelineCsvMaxFiles = 5)
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

internal sealed record PendingNotification(
    string Title,
    string Text,
    ToolTipIcon Icon,
    int TimeoutMs,
    bool CountsAsUnreadEvent);

internal sealed record EventSnapshot(
    int EventId,
    long? RecordId,
    string? LogName,
    string? MachineName,
    DateTime? TimeCreated,
    string Xml,
    IReadOnlyDictionary<string, string> Data)
{
    public static EventSnapshot From(EventRecord r)
    {
        // Only keep what we need; EventRecord must be disposed by the caller.
        var xml = r.ToXml();
        var data = ParseEventData(xml);
        return new EventSnapshot(r.Id, r.RecordId, r.LogName, r.MachineName, r.TimeCreated, xml, data);
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
