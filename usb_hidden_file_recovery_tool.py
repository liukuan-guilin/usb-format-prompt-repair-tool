# -*- coding: utf-8 -*-
import csv
import os
import queue
import shutil
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText


APP_TITLE = "U盘隐藏文件恢复工具"
ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_ROOT = ROOT_DIR / "repair-output"
FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4


def format_bytes(num: int) -> str:
    value = float(num)
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024
        idx += 1
    return f"{value:.2f} {units[idx]}"


def run_powershell(script: str) -> str:
    completed = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return completed.stdout.strip()


def run_powershell_json(script: str):
    import json

    output = run_powershell(script)
    if not output:
        return []
    data = json.loads(output)
    if isinstance(data, list):
        return data
    return [data]


def get_usb_volumes():
    script = r"""
$result = @()
$volumes = Get-Volume | Where-Object { $_.DriveLetter }
foreach ($volume in $volumes) {
    try {
        $partition = Get-Partition -DriveLetter $volume.DriveLetter -ErrorAction Stop
        $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
        if ($disk.BusType -eq 'USB' -or $disk.FriendlyName -match 'USB|Flash|Removable|UFD') {
            $result += [pscustomobject]@{
                DriveLetter = $volume.DriveLetter
                Label       = $volume.FileSystemLabel
                FileSystem  = $volume.FileSystem
                Size        = $volume.Size
                Free        = $volume.SizeRemaining
                DiskNumber  = $disk.Number
                DiskName    = $disk.FriendlyName
            }
        }
    } catch {}
}
$result | ConvertTo-Json -Depth 4 -Compress
"""
    return run_powershell_json(script)


def get_file_attrs(path: Path) -> int:
    try:
        return getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except Exception:
        return 0


def has_hidden_or_system(path: Path) -> bool:
    attrs = get_file_attrs(path)
    return bool(attrs & FILE_ATTRIBUTE_HIDDEN or attrs & FILE_ATTRIBUTE_SYSTEM)


def attrs_to_text(attrs: int) -> str:
    flags = []
    if attrs & FILE_ATTRIBUTE_READONLY:
        flags.append("ReadOnly")
    if attrs & FILE_ATTRIBUTE_HIDDEN:
        flags.append("Hidden")
    if attrs & FILE_ATTRIBUTE_SYSTEM:
        flags.append("System")
    return "|".join(flags) if flags else "Normal"


def export_listing_csv(output_path: Path, rows):
    rows = list(rows)
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["path", "attributes", "size", "modified"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def list_root_items(root_path: Path):
    rows = []
    for item in sorted(root_path.iterdir(), key=lambda p: p.name.lower()):
        try:
            stat = item.stat(follow_symlinks=False)
            rows.append(
                {
                    "path": str(item),
                    "attributes": attrs_to_text(getattr(stat, "st_file_attributes", 0)),
                    "size": "" if item.is_dir() else stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(sep=" ", timespec="seconds"),
                }
            )
        except Exception:
            rows.append({"path": str(item), "attributes": "UNKNOWN", "size": "", "modified": ""})
    return rows


def scan_hidden_or_system(root_path: Path, log=None):
    rows = []
    counter = 0
    for current_root, dirnames, filenames in os.walk(root_path):
        all_names = list(dirnames) + list(filenames)
        for name in all_names:
            counter += 1
            item = Path(current_root) / name
            try:
                stat = item.stat(follow_symlinks=False)
                attrs = getattr(stat, "st_file_attributes", 0)
                if attrs & FILE_ATTRIBUTE_HIDDEN or attrs & FILE_ATTRIBUTE_SYSTEM:
                    rows.append(
                        {
                            "path": str(item),
                            "attributes": attrs_to_text(attrs),
                            "size": "" if item.is_dir() else stat.st_size,
                            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(sep=" ", timespec="seconds"),
                        }
                    )
            except Exception:
                continue
        if log and counter and counter % 1000 == 0:
            log(f"已扫描 {counter} 个项目...")
    return rows


def get_suspicious_root_files(root_path: Path):
    suspicious_exts = {".lnk", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta", ".cmd", ".bat", ".pif", ".scr", ".com"}
    results = []
    for item in root_path.iterdir():
        if not item.is_file():
            continue
        name_lower = item.name.lower()
        if name_lower == "autorun.inf" or item.suffix.lower() in suspicious_exts:
            results.append(item)
    return sorted(results, key=lambda p: p.name.lower())


def run_attrib_restore(drive_letter: str):
    target = f"{drive_letter}:\\*.*"
    subprocess.run(
        ["cmd.exe", "/c", "attrib", "-h", "-r", "-s", "/s", "/d", target],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def move_to_quarantine(files, quarantine_dir: Path):
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    moved = []
    for src in files:
        dest = quarantine_dir / src.name
        idx = 1
        while dest.exists():
            dest = quarantine_dir / f"{src.stem}_{idx}{src.suffix}"
            idx += 1
        shutil.move(str(src), str(dest))
        moved.append(dest)
    return moved


class HiddenRecoveryApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("980x740")
        self.root.minsize(900, 680)
        self.queue = queue.Queue()
        self.current_output_dir = None

        self.output_root_var = tk.StringVar(value=str(DEFAULT_OUTPUT_ROOT))
        self.quarantine_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="就绪")

        self._build_ui()
        self.refresh_volumes()
        self.root.after(150, self._poll_queue)

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=12)
        top.pack(fill="both", expand=True)

        ttk.Label(
            top,
            text="U盘隐藏文件恢复工具",
            font=("Microsoft YaHei UI", 18, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            top,
            text="适用于文件被隐藏、文件夹变快捷方式、恢复可见后名字乱码这类常见中毒场景。这个工具不会格式化U盘。",
            wraplength=920,
        ).pack(anchor="w", pady=(6, 12))

        warning = ttk.LabelFrame(top, text="什么时候适合用这个工具", padding=10)
        warning.pack(fill="x")
        ttk.Label(
            warning,
            text=(
                "适用：U盘看起来空空的、文件夹变成快捷方式、根目录出现 autorun.inf 或脚本文件、"
                "去掉隐藏后文件名乱码但文件内容还在。\n"
                "不适用：Windows 提示需要格式化、文件系统 RAW、U盘频繁掉线、整盘都读不出来。"
            ),
            wraplength=900,
        ).pack(anchor="w")

        disk_frame = ttk.LabelFrame(top, text="1. 选择 USB 盘", padding=10)
        disk_frame.pack(fill="x", pady=(12, 0))
        columns = ("letter", "label", "fs", "size", "free", "disk")
        self.tree = ttk.Treeview(disk_frame, columns=columns, show="headings", height=6)
        headings = {
            "letter": "盘符",
            "label": "卷标",
            "fs": "文件系统",
            "size": "容量",
            "free": "剩余",
            "disk": "设备名称",
        }
        widths = {"letter": 70, "label": 150, "fs": 110, "size": 120, "free": 120, "disk": 360}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="center" if col != "disk" else "w")
        self.tree.pack(fill="x")
        ttk.Button(disk_frame, text="刷新 USB 盘", command=self.refresh_volumes).pack(anchor="w", pady=(10, 0))

        options = ttk.LabelFrame(top, text="2. 恢复选项", padding=10)
        options.pack(fill="x", pady=(12, 0))
        row = ttk.Frame(options)
        row.pack(fill="x")
        ttk.Label(row, text="输出目录：").pack(side="left")
        ttk.Entry(row, textvariable=self.output_root_var).pack(side="left", fill="x", expand=True, padx=(6, 6))
        ttk.Button(row, text="选择目录", command=self.choose_output_dir).pack(side="left")
        ttk.Checkbutton(
            options,
            text="把根目录常见可疑文件移到隔离区（推荐）",
            variable=self.quarantine_var,
        ).pack(anchor="w", pady=(10, 0))

        actions = ttk.Frame(top)
        actions.pack(fill="x", pady=(12, 0))
        ttk.Button(actions, text="开始恢复", command=self.start_recovery).pack(side="left")
        ttk.Button(actions, text="打开输出目录", command=self.open_output_dir).pack(side="left", padx=(8, 0))

        progress_frame = ttk.Frame(top)
        progress_frame.pack(fill="x", pady=(12, 0))
        self.progress = ttk.Progressbar(progress_frame, mode="indeterminate")
        self.progress.pack(fill="x")
        ttk.Label(progress_frame, textvariable=self.status_var).pack(anchor="w", pady=(6, 0))

        log_frame = ttk.LabelFrame(top, text="运行日志", padding=10)
        log_frame.pack(fill="both", expand=True, pady=(12, 0))
        self.log = ScrolledText(log_frame, height=18, font=("Consolas", 10))
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")

    def append_log(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def set_status(self, text: str):
        self.status_var.set(text)

    def choose_output_dir(self):
        path = filedialog.askdirectory(initialdir=self.output_root_var.get() or str(ROOT_DIR))
        if path:
            self.output_root_var.set(path)

    def open_output_dir(self):
        path = self.current_output_dir or self.output_root_var.get()
        if path and Path(path).exists():
            os.startfile(path)
        else:
            messagebox.showinfo(APP_TITLE, "还没有可打开的输出目录。")

    def refresh_volumes(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        try:
            volumes = get_usb_volumes()
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"读取 USB 盘失败：\n{exc}")
            return

        for volume in volumes:
            self.tree.insert(
                "",
                "end",
                values=(
                    volume["DriveLetter"],
                    volume.get("Label", ""),
                    volume.get("FileSystem", ""),
                    format_bytes(int(volume["Size"])),
                    format_bytes(int(volume["Free"])),
                    volume["DiskName"],
                ),
            )
        self.append_log("已刷新 USB 盘列表。")

    def selected_drive(self):
        selection = self.tree.selection()
        if not selection:
            return None
        return self.tree.item(selection[0], "values")[0]

    def start_recovery(self):
        drive_letter = self.selected_drive()
        if not drive_letter:
            messagebox.showwarning(APP_TITLE, "请先选择一个 USB 盘。")
            return

        output_root = Path(self.output_root_var.get()).expanduser()
        output_root.mkdir(parents=True, exist_ok=True)
        confirm = messagebox.askyesno(
            APP_TITLE,
            f"将处理 {drive_letter}: 盘。\n\n"
            "这个工具会尝试恢复隐藏文件显示，并可选隔离根目录可疑文件。\n"
            "它不会格式化U盘。\n\n"
            "是否继续？",
        )
        if not confirm:
            return

        self.progress.start(10)
        self.set_status("正在处理...")
        worker = threading.Thread(
            target=self._worker,
            args=(drive_letter, output_root, bool(self.quarantine_var.get())),
            daemon=True,
        )
        worker.start()

    def _worker(self, drive_letter: str, output_root: Path, quarantine: bool):
        def log(msg: str):
            self.queue.put(("log", msg))

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = output_root / f"hidden-files-{drive_letter}-{timestamp}"
        output_dir.mkdir(parents=True, exist_ok=True)
        self.current_output_dir = str(output_dir)
        root_path = Path(f"{drive_letter}:\\")

        try:
            log(f"输出目录：{output_dir}")
            before_rows = list_root_items(root_path)
            export_listing_csv(output_dir / "root-before.csv", before_rows)
            log("已保存根目录修复前清单。")

            hidden_rows = scan_hidden_or_system(root_path, log=log)
            export_listing_csv(output_dir / "hidden-or-system-before.csv", hidden_rows)
            log(f"修复前发现隐藏/系统项目：{len(hidden_rows)} 个。")

            suspicious_files = get_suspicious_root_files(root_path)
            suspicious_rows = []
            for item in suspicious_files:
                stat = item.stat()
                suspicious_rows.append(
                    {
                        "path": str(item),
                        "attributes": attrs_to_text(getattr(stat, "st_file_attributes", 0)),
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(sep=" ", timespec="seconds"),
                    }
                )
            export_listing_csv(output_dir / "suspicious-root-files-before.csv", suspicious_rows)
            log(f"根目录可疑文件：{len(suspicious_rows)} 个。")

            log("正在恢复隐藏属性...")
            run_attrib_restore(drive_letter)
            log("attrib 已执行完成。")

            moved = []
            if quarantine and suspicious_files:
                moved = move_to_quarantine(suspicious_files, output_dir / "quarantine")
                log(f"已移动到隔离区：{len(moved)} 个文件。")

            after_rows = list_root_items(root_path)
            export_listing_csv(output_dir / "root-after.csv", after_rows)
            log("已保存根目录修复后清单。")

            summary = [
                f"DriveLetter={drive_letter}",
                f"OutputDir={output_dir}",
                f"HiddenOrSystemBefore={len(hidden_rows)}",
                f"SuspiciousRootFilesBefore={len(suspicious_rows)}",
                f"Quarantined={len(moved)}",
                "Status=Completed",
            ]
            (output_dir / "summary.txt").write_text("\n".join(summary), encoding="utf-8")

            log("关于乱码文件名：")
            log("- 如果文件内容还能正常打开，先复制到硬盘再改名。")
            log("- 如果文件名和内容都不正常，就改走文件恢复路线。")
            self.queue.put(("done", f"恢复完成。\n输出目录：{output_dir}"))

        except Exception as exc:
            (output_dir / "error.txt").write_text(str(exc), encoding="utf-8")
            self.queue.put(("error", f"{exc}\n\n输出目录：{output_dir}"))

    def _poll_queue(self):
        while True:
            try:
                kind, payload = self.queue.get_nowait()
            except queue.Empty:
                break

            if kind == "log":
                self.append_log(payload)
            elif kind == "done":
                self.progress.stop()
                self.set_status("完成")
                self.append_log(payload)
                messagebox.showinfo(APP_TITLE, payload)
            elif kind == "error":
                self.progress.stop()
                self.set_status("已停止")
                self.append_log("错误：" + payload)
                messagebox.showerror(APP_TITLE, payload)

        self.root.after(150, self._poll_queue)


def main():
    DEFAULT_OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    root = tk.Tk()
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    HiddenRecoveryApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
