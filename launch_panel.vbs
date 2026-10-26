' Launch sp26_panel.py with pythonw (no console window).
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
base = fso.GetParentFolderName(WScript.ScriptFullName)
pyw = sh.Environment("PROCESS")("SP26PYW")
If pyw = "" Then pyw = "pythonw"
sh.CurrentDirectory = base
sh.Run pyw & " " & Chr(34) & base & "\sp26_panel.py" & Chr(34), 0, False
