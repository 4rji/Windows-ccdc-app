using System.Diagnostics;
using System.Text;
using System.Windows.Forms;

namespace LocalEventNotifier;

internal sealed class EventDetailsForm : Form
{
    private readonly Label _header;
    private readonly TextBox _summary;
    private readonly TextBox _xml;
    private readonly Button _btnOpenEventViewer;
    private readonly Button _btnCopyWevtutil;
    private readonly Button _btnCopyXml;
    private readonly Button _btnClose;

    private EventSnapshot? _snapshot;

    public EventDetailsForm()
    {
        Text = "Event Details";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new System.Drawing.Size(720, 420);

        _header = new Label
        {
            Dock = DockStyle.Top,
            AutoSize = false,
            Height = 44,
            Padding = new Padding(12, 12, 12, 0),
            Font = new System.Drawing.Font("Segoe UI", 11, System.Drawing.FontStyle.Bold),
            Text = "Event"
        };

        var tabs = new TabControl { Dock = DockStyle.Fill };
        var tabSummary = new TabPage("Summary");
        var tabXml = new TabPage("XML");

        _summary = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Font = new System.Drawing.Font("Consolas", 10)
        };
        tabSummary.Controls.Add(_summary);

        _xml = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Both,
            WordWrap = false,
            Font = new System.Drawing.Font("Consolas", 10)
        };
        tabXml.Controls.Add(_xml);

        tabs.TabPages.Add(tabSummary);
        tabs.TabPages.Add(tabXml);

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 52,
            Padding = new Padding(10, 10, 10, 10),
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false
        };

        _btnOpenEventViewer = new Button { Text = "Open Event Viewer", AutoSize = true };
        _btnOpenEventViewer.Click += (_, _) => OpenEventViewer();

        _btnCopyWevtutil = new Button { Text = "Copy wevtutil", AutoSize = true };
        _btnCopyWevtutil.Click += (_, _) => CopyWevtutil();

        _btnCopyXml = new Button { Text = "Copy XML", AutoSize = true };
        _btnCopyXml.Click += (_, _) => CopyXml();

        _btnClose = new Button { Text = "Close", AutoSize = true };
        _btnClose.Click += (_, _) => Close();

        buttons.Controls.Add(_btnOpenEventViewer);
        buttons.Controls.Add(_btnCopyWevtutil);
        buttons.Controls.Add(_btnCopyXml);
        buttons.Controls.Add(_btnClose);

        Controls.Add(tabs);
        Controls.Add(buttons);
        Controls.Add(_header);
    }

    public void SetSnapshot(EventSnapshot snapshot)
    {
        _snapshot = snapshot;

        var log = snapshot.LogName ?? "(log)";
        var rid = snapshot.RecordId?.ToString() ?? "(n/a)";
        var time = snapshot.TimeCreated?.ToString("yyyy-MM-dd HH:mm:ss") ?? "(n/a)";
        _header.Text = $"{log}  EventID {snapshot.EventId}  RecordID {rid}  {time}";

        _summary.Text = BuildSummary(snapshot);
        _xml.Text = snapshot.Xml;
    }

    private static string BuildSummary(EventSnapshot s)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"LogName: {s.LogName ?? "(n/a)"}");
        sb.AppendLine($"Machine: {s.MachineName ?? "(n/a)"}");
        sb.AppendLine($"EventID: {s.EventId}");
        sb.AppendLine($"RecordID: {s.RecordId?.ToString() ?? "(n/a)"}");
        sb.AppendLine($"Time: {s.TimeCreated?.ToString("yyyy-MM-dd HH:mm:ss") ?? "(n/a)"}");

        // A few common fields depending on event type.
        var d = s.Data;
        var targetUser = d.GetAny("TargetDomainName") is { } tdom && d.GetAny("TargetUserName") is { } tuser
            ? $"{tdom}\\{tuser}"
            : d.GetAny("TargetUserName");
        var subjectUser = d.GetAny("SubjectDomainName") is { } sdom && d.GetAny("SubjectUserName") is { } suser
            ? $"{sdom}\\{suser}"
            : d.GetAny("SubjectUserName");

        if (!string.IsNullOrWhiteSpace(subjectUser))
        {
            sb.AppendLine($"SubjectUser: {subjectUser}");
        }
        if (!string.IsNullOrWhiteSpace(targetUser))
        {
            sb.AppendLine($"TargetUser: {targetUser}");
        }

        var ip = d.GetAny("IpAddress") ?? d.GetAny("WorkstationName");
        if (!string.IsNullOrWhiteSpace(ip))
        {
            sb.AppendLine($"IP/Host: {ip}");
        }

        var svc = d.GetAny("ServiceName");
        if (!string.IsNullOrWhiteSpace(svc))
        {
            sb.AppendLine($"ServiceName: {svc}");
        }

        sb.AppendLine();
        sb.AppendLine("EventData:");
        foreach (var kvp in d.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine($"{kvp.Key} = {kvp.Value}");
        }

        return sb.ToString();
    }

    private void OpenEventViewer()
    {
        try
        {
            Process.Start(new ProcessStartInfo("eventvwr.msc") { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Could not open Event Viewer", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void CopyWevtutil()
    {
        if (_snapshot is null)
        {
            MessageBox.Show(this, "No event loaded.", "Copy wevtutil", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var log = string.IsNullOrWhiteSpace(_snapshot.LogName) ? "Security" : _snapshot.LogName!;
        if (_snapshot.RecordId is null)
        {
            MessageBox.Show(this, "This event has no RecordID.", "Copy wevtutil", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        var cmd = $"wevtutil qe \"{log}\" /q:\"*[System[(EventRecordID={_snapshot.RecordId.Value})]]\" /f:RenderedText /c:1";
        Clipboard.SetText(cmd);
    }

    private void CopyXml()
    {
        if (_snapshot is null)
        {
            MessageBox.Show(this, "No event loaded.", "Copy XML", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        Clipboard.SetText(_snapshot.Xml ?? "");
    }
}
