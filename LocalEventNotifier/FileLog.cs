using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows.Forms;

namespace LocalEventNotifier;

internal sealed class FileLog : IDisposable
{
    private readonly string _path;
    private readonly int _maxBytes;
    private readonly int _maxFiles;
    private readonly bool _includeXml;

    private readonly ConcurrentQueue<string> _queue = new();
    private readonly SemaphoreSlim _signal = new(0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _worker;

    private readonly object _ioLock = new();

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };

    private FileLog(string path, int maxBytes, int maxFiles, bool includeXml)
    {
        _path = path;
        _maxBytes = Math.Max(64 * 1024, maxBytes);
        _maxFiles = Math.Clamp(maxFiles, 1, 50);
        _includeXml = includeXml;

        EnsureDirExists();
        _worker = Task.Run(WorkerLoop);
    }

    public static FileLog? TryCreate(AppSettings settings)
    {
        if (!settings.EnableFileLog) return null;

        try
        {
            var path = ResolvePath(settings.LogPath);
            return new FileLog(
                path: path,
                maxBytes: settings.LogMaxBytes,
                maxFiles: settings.LogMaxFiles,
                includeXml: settings.LogIncludeXml);
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"FileLog disabled: {ex}");
            return null;
        }
    }

    public string PathOnDisk => _path;

    public string DirectoryOnDisk => System.IO.Path.GetDirectoryName(_path) ?? AppContext.BaseDirectory;

    public void LogEvent(EventSnapshot e, string title, string message, ToolTipIcon icon)
    {
        var entry = new LogEntry(
            TsUtc: DateTimeOffset.UtcNow,
            Kind: "event",
            Level: IconToLevel(icon),
            Title: title,
            Message: message,
            EventId: e.EventId,
            RecordId: e.RecordId,
            LogName: e.LogName,
            MachineName: e.MachineName,
            TimeCreated: e.TimeCreated,
            Wevtutil: BuildWevtutil(e),
            Xml: _includeXml ? e.Xml : null);

        Enqueue(entry);
    }

    public void LogError(string title, string message, Exception? ex = null)
    {
        var entry = new LogEntry(
            TsUtc: DateTimeOffset.UtcNow,
            Kind: "app",
            Level: "error",
            Title: title,
            Message: ex is null ? message : $"{message}\n{ex}",
            EventId: null,
            RecordId: null,
            LogName: null,
            MachineName: Environment.MachineName,
            TimeCreated: null,
            Wevtutil: null,
            Xml: null);

        Enqueue(entry);
    }

    public void OpenLogFile()
    {
        try
        {
            EnsureDirExists();
            if (!File.Exists(_path))
            {
                File.WriteAllText(_path, "");
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = _path,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"OpenLogFile failed: {ex}");
        }
    }

    public void OpenLogFolder()
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
            Debug.WriteLine($"OpenLogFolder failed: {ex}");
        }
    }

    private void Enqueue(LogEntry entry)
    {
        try
        {
            var line = JsonSerializer.Serialize(entry, JsonOptions);
            _queue.Enqueue(line);
            _signal.Release();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"FileLog enqueue failed: {ex}");
        }
    }

    private async Task WorkerLoop()
    {
        var batch = new List<string>(256);

        while (!_cts.IsCancellationRequested)
        {
            try
            {
                // Wait for at least one item, or flush periodically.
                await _signal.WaitAsync(TimeSpan.FromSeconds(1), _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Ignore and try flushing whatever is queued.
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
                Debug.WriteLine($"FileLog write failed: {ex}");
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

            using var fs = new FileStream(_path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            using var sw = new StreamWriter(fs);
            foreach (var line in batch)
            {
                sw.WriteLine(line);
            }
        }
    }

    private void RotateIfNeeded()
    {
        try
        {
            var fi = new FileInfo(_path);
            if (!fi.Exists) return;
            if (fi.Length < _maxBytes) return;

            // events.ndjson -> events.1.ndjson -> ... -> events.N.ndjson
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
            Debug.WriteLine($"FileLog rotate failed: {ex}");
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
        var dir = DirectoryOnDisk;
        Directory.CreateDirectory(dir);
    }

    private static string ResolvePath(string? configuredPath)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return System.IO.Path.Combine(AppContext.BaseDirectory, "logs", "events.ndjson");
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

    private static string IconToLevel(ToolTipIcon icon) => icon switch
    {
        ToolTipIcon.Error => "error",
        ToolTipIcon.Warning => "warn",
        _ => "info"
    };

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _signal.Release(); } catch { }
        try { _worker.Wait(TimeSpan.FromSeconds(2)); } catch { }
        try { _cts.Dispose(); } catch { }
        try { _signal.Dispose(); } catch { }
    }

    private sealed record LogEntry(
        DateTimeOffset TsUtc,
        string Kind,
        string Level,
        string Title,
        string Message,
        int? EventId,
        long? RecordId,
        string? LogName,
        string? MachineName,
        DateTime? TimeCreated,
        string? Wevtutil,
        string? Xml);
}
