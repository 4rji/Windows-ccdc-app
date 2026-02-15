using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Windows.Forms;

namespace LocalEventNotifier;

// RFC-4180-ish CSV writer tailored for Timeline Explorer friendly timelines.
internal sealed class TimelineCsvLog : IDisposable
{
    // ForensicTimeliner-compatible header (widely used with Timeline Explorer).
    // DateTime,TimestampInfo,ArtifactName,Tool,Description,DataDetails,DataPath,FileExtension,EventId,User,Computer,FileSize,IPAddress,SourceAddress,DestinationAddress,SHA1,Count,EvidencePath
    private const string Header =
        "DateTime,TimestampInfo,ArtifactName,Tool,Description,DataDetails,DataPath,FileExtension,EventId,User,Computer,FileSize,IPAddress,SourceAddress,DestinationAddress,SHA1,Count,EvidencePath";

    private readonly string _path;
    private readonly int _maxBytes;
    private readonly int _maxFiles;

    private readonly ConcurrentQueue<string> _queue = new();
    private readonly SemaphoreSlim _signal = new(0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _worker;

    private readonly object _ioLock = new();

    private TimelineCsvLog(string path, int maxBytes, int maxFiles)
    {
        _path = path;
        _maxBytes = Math.Max(64 * 1024, maxBytes);
        _maxFiles = Math.Clamp(maxFiles, 1, 50);

        EnsureDirExists();
        _worker = Task.Run(WorkerLoop);
    }

    public static TimelineCsvLog? TryCreate(AppSettings settings)
    {
        if (!settings.EnableTimelineCsvLog) return null;

        try
        {
            var path = ResolvePath(settings.TimelineCsvPath);
            return new TimelineCsvLog(
                path: path,
                maxBytes: settings.TimelineCsvMaxBytes,
                maxFiles: settings.TimelineCsvMaxFiles);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"TimelineCsvLog disabled: {ex}");
            return null;
        }
    }

    public string PathOnDisk => _path;

    public string DirectoryOnDisk => System.IO.Path.GetDirectoryName(_path) ?? AppContext.BaseDirectory;

    public void LogEvent(EventSnapshot e, string title, string message, ToolTipIcon icon)
    {
        // Prefer the event's own timestamp; fall back to "now".
        var dtLocal = e.TimeCreated ?? DateTime.Now;
        var dateTime = dtLocal.ToString("yyyy-MM-dd HH:mm:ss.fff");

        var d = e.Data;
        var user =
            JoinDomainUser(d.GetAny("TargetDomainName", "RealmName", "SamAccountDomain"), d.GetAny("TargetUserName", "AccountName", "SamAccountName"))
            ?? JoinDomainUser(d.GetAny("SubjectDomainName"), d.GetAny("SubjectUserName"))
            ?? "";

        var ip = d.GetAny("IpAddress") ?? d.GetAny("WorkstationName") ?? "";

        var wevtutil = BuildWevtutil(e) ?? "";

        // Try to keep the "DataDetails" field dense but still readable in TLE.
        var details = new StringBuilder();
        details.AppendLine(message);
        details.AppendLine();
        details.AppendLine($"RecordID: {e.RecordId?.ToString() ?? "(n/a)"}");
        if (!string.IsNullOrWhiteSpace(wevtutil))
        {
            details.AppendLine(wevtutil);
        }

        // Map into the standard TLE timeline schema.
        var row = string.Join(",",
            Csv(dateTime),                                 // DateTime
            Csv("TimeCreated"),                            // TimestampInfo
            Csv("WindowsEventLog"),                        // ArtifactName
            Csv("LocalEventNotifier"),                     // Tool
            Csv(title),                                    // Description
            Csv(details.ToString().TrimEnd()),             // DataDetails
            Csv(e.LogName ?? "Security"),                  // DataPath
            Csv(""),                                       // FileExtension
            Csv(e.EventId.ToString()),                     // EventId
            Csv(user),                                     // User
            Csv(e.MachineName ?? Environment.MachineName), // Computer
            Csv(""),                                       // FileSize
            Csv(ip),                                       // IPAddress
            Csv(ip),                                       // SourceAddress
            Csv(e.MachineName ?? ""),                      // DestinationAddress
            Csv(""),                                       // SHA1
            Csv("1"),                                      // Count
            Csv(wevtutil));                                // EvidencePath

        Enqueue(row);
    }

    public void LogError(string title, string message, Exception? ex = null)
    {
        var dateTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var details = ex is null ? message : $"{message}\n{ex}";

        var row = string.Join(",",
            Csv(dateTime),
            Csv("App"),
            Csv("LocalEventNotifier"),
            Csv("LocalEventNotifier"),
            Csv($"ERROR: {title}"),
            Csv(details),
            Csv(""),
            Csv(""),
            Csv(""),
            Csv(""),
            Csv(Environment.MachineName),
            Csv(""),
            Csv(""),
            Csv(""),
            Csv(""),
            Csv(""),
            Csv("1"),
            Csv(""));

        Enqueue(row);
    }

    public void OpenCsvFile()
    {
        try
        {
            EnsureDirExists();
            EnsureHeader();

            Process.Start(new ProcessStartInfo
            {
                FileName = _path,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"OpenCsvFile failed: {ex}");
        }
    }

    public void OpenFolder()
    {
        try
        {
            EnsureDirExists();
            Process.Start(new ProcessStartInfo
            {
                FileName = DirectoryOnDisk,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"OpenFolder failed: {ex}");
        }
    }

    private void Enqueue(string row)
    {
        try
        {
            _queue.Enqueue(row);
            _signal.Release();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"TimelineCsvLog enqueue failed: {ex}");
        }
    }

    private async Task WorkerLoop()
    {
        var batch = new List<string>(256);

        while (!_cts.IsCancellationRequested)
        {
            try
            {
                await _signal.WaitAsync(TimeSpan.FromSeconds(1), _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // ignore
            }

            batch.Clear();
            while (batch.Count < 512 && _queue.TryDequeue(out var line))
            {
                batch.Add(line);
            }
            if (batch.Count == 0) continue;

            try
            {
                WriteBatch(batch);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"TimelineCsvLog write failed: {ex}");
            }
        }

        // Best-effort final flush.
        try
        {
            batch.Clear();
            while (batch.Count < 4096 && _queue.TryDequeue(out var line))
            {
                batch.Add(line);
            }
            if (batch.Count > 0) WriteBatch(batch);
        }
        catch { }
    }

    private void WriteBatch(List<string> batch)
    {
        lock (_ioLock)
        {
            EnsureDirExists();
            RotateIfNeeded();
            EnsureHeader();

            using var fs = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            using var sw = new StreamWriter(fs, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            foreach (var line in batch)
            {
                sw.WriteLine(line);
            }
        }
    }

    private void EnsureHeader()
    {
        try
        {
            var fi = new FileInfo(_path);
            if (!fi.Exists || fi.Length == 0)
            {
                using var fs = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                using var sw = new StreamWriter(fs, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                sw.WriteLine(Header);
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"EnsureHeader failed: {ex}");
        }
    }

    private void RotateIfNeeded()
    {
        try
        {
            var fi = new FileInfo(_path);
            if (!fi.Exists) return;
            if (fi.Length < _maxBytes) return;

            for (var i = _maxFiles - 1; i >= 1; i--)
            {
                var src = SuffixPath(_path, i);
                var dst = SuffixPath(_path, i + 1);
                if (File.Exists(dst)) File.Delete(dst);
                if (File.Exists(src)) File.Move(src, dst);
            }

            var first = SuffixPath(_path, 1);
            if (File.Exists(first)) File.Delete(first);
            File.Move(_path, first);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"RotateIfNeeded failed: {ex}");
        }
    }

    private static string SuffixPath(string path, int n)
    {
        var dir = System.IO.Path.GetDirectoryName(path) ?? "";
        var name = System.IO.Path.GetFileNameWithoutExtension(path);
        var ext = System.IO.Path.GetExtension(path);
        return System.IO.Path.Combine(dir, $"{name}.{n}{ext}");
    }

    private void EnsureDirExists()
    {
        Directory.CreateDirectory(DirectoryOnDisk);
    }

    private static string ResolvePath(string? configuredPath)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return System.IO.Path.Combine(AppContext.BaseDirectory, "logs", "timeline.csv");
        }

        var p = configuredPath.Trim();
        if (System.IO.Path.IsPathRooted(p))
        {
            return p;
        }

        return System.IO.Path.Combine(AppContext.BaseDirectory, p);
    }

    private static string? BuildWevtutil(EventSnapshot s)
    {
        var log = string.IsNullOrWhiteSpace(s.LogName) ? "Security" : s.LogName!;
        if (s.RecordId is null) return null;
        return $"wevtutil qe \"{log}\" /q:\"*[System[(EventRecordID={s.RecordId.Value})]]\" /f:RenderedText /c:1";
    }

    private static string? JoinDomainUser(string? domain, string? user)
    {
        domain = string.IsNullOrWhiteSpace(domain) ? null : domain.Trim();
        user = string.IsNullOrWhiteSpace(user) ? null : user.Trim();
        if (domain is null && user is null) return null;
        if (domain is null) return user!;
        if (user is null) return domain;
        return $"{domain}\\{user}";
    }

    private static string Csv(string? s)
    {
        s ??= "";
        s = s.Replace("\0", "", StringComparison.Ordinal);

        var mustQuote = s.Contains(',') || s.Contains('"') || s.Contains('\n') || s.Contains('\r');
        if (!mustQuote)
        {
            return s;
        }

        return "\"" + s.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _signal.Release(); } catch { }
        try { _worker.Wait(TimeSpan.FromSeconds(2)); } catch { }
        try { _cts.Dispose(); } catch { }
        try { _signal.Dispose(); } catch { }
    }
}
