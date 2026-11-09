# Combined Task Scheduler Parser

A screenshare tool that scans every scheduled task on a Windows PC and flags the ones that look like a Task Scheduler bypass or persistence. It combines the checks from the popular task parsers and the Task Scheduler methods from the SS guides into one scan.

It's **read-only**. It never creates, edits or deletes a task.

## What it checks

- **Task files on disk** in `System32\Tasks`, `System32\Tasks_Migrated` and `Windows\Tasks` (command, arguments, triggers, author, run-as user)
- **TaskCache registry** (`Tasks` and `Tree`), compared with the files on disk. A task that's in the registry with no file usually means the file got deleted before the SS.
- **Signatures** on the action exe and on any file path inside the arguments
- **Suspicious launchers** like cmd, powershell, mshta, wscript, rundll32, regsvr32 and conhost
- **Suspicious arguments** like `-enc`, base64, `iex`, download commands, hidden windows and URLs
- **Logon and boot triggers** on tasks that aren't Windows' own (anything outside `\Microsoft\`)
- **Highest privilege** run levels, actions outside normal folders, unicode characters in task names
- **Recently modified** task files (last 24 hours by default)
- **IFEO debugger entries**, which redirect one program to another

Every task gets a score and a rating: **HIGH**, **MEDIUM**, **LOW** or **CLEAN**.

## Download

Get `CombinedTaskParser.exe` from the [latest release](https://github.com/aaa1243/task-parser/releases/latest). It asks for admin when you open it, since the registry and IFEO checks need it.

## Usage

Run the exe, or run the script from an admin CMD:

```
powershell -ExecutionPolicy Bypass -File .\CombinedTaskParser.ps1
```

| Option | What it does |
|---|---|
| `-SinceHours 48` | Changes the "recently modified" window (default 24) |
| `-OutDir <path>` | Where results go (default `C:\SSTools\TaskParser`) |
| `-IncludeMicrosoft` | Also lists clean tasks in the console |
| `-NoOpen` | Doesn't open the results folder at the end |

Results show in color in the console, and a CSV plus a txt report get saved to the output folder.

## Limits

- For registry-only tasks, the command is pulled from the binary Actions data as a best guess. Check those by hand in Registry Explorer.
- This doesn't replace dumping the Schedule service in System Informer in the first 15 minutes. A task deleted from both disk and registry only shows up in memory.

## Building

Every push builds the exe on GitHub Actions. The build registers a fake bypass-style task, runs the parser, and fails if that task isn't flagged HIGH. Push a tag like `v1.0.0` to publish a release.

## License

MIT
