param([string]$Title = "CredLens", [string]$Text = "")
# Windows toast notification for a caught credential (best effort).
try {
  [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
  $tpl = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
  $nodes = $tpl.GetElementsByTagName("text")
  $nodes.Item(0).AppendChild($tpl.CreateTextNode($Title)) | Out-Null
  $nodes.Item(1).AppendChild($tpl.CreateTextNode($Text)) | Out-Null
  $toast = [Windows.UI.Notifications.ToastNotification]::new($tpl)
  $appId = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
  [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
} catch {
  exit 1
}
