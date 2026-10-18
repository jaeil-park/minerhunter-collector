"""수집기가 PC 를 바꾸지 않는지 기계적으로 확인한다 (CI 와 로컬에서 실행).

collector.ps1 에서 시스템을 바꾸는 명령(프로세스 종료, 레지스트리·서비스·예약작업·Defender 변경,
파일 삭제, 원격 코드 실행 등)을 찾는다. 아래 ALLOWED 의 용도 외에 하나라도 있으면 실패한다.

    python verify.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent / "collector.ps1"

FORBIDDEN = [
    "Stop-Process", "Stop-Service", "Set-Service", "Remove-Service", "New-Service",
    "Set-ItemProperty", "New-ItemProperty", "Remove-ItemProperty", "Rename-ItemProperty", "New-Item", "Move-Item",
    "Copy-Item", "Rename-Item", "Remove-Item", "Clear-Content", "Set-Content", "Add-Content", "Out-File",
    "Register-ScheduledTask", "Unregister-ScheduledTask", "Set-ScheduledTask", "Disable-ScheduledTask",
    "Set-MpPreference", "Add-MpPreference", "Remove-MpPreference", "Remove-CimInstance", "Set-CimInstance",
    "Invoke-CimMethod", "Remove-WmiObject", "Invoke-WmiMethod", "Invoke-Expression", "iex", "Start-Process",
    "reg", "sc", "schtasks", "netsh", "takeown", "icacls", "bcdedit", "vssadmin", "Restart-Computer",
    "Stop-Computer", "WriteAllText", "WriteAllBytes", "DownloadString", "DownloadFile", "Invoke-WebRequest",
    "Invoke-RestMethod",
]

# 허용: 정확히 이 줄 패턴에서, 정해진 횟수만
ALLOWED = {
    "WriteAllText": (r"\[IO\.File\]::WriteAllText\(\$OutFile, \$json,", 1, "수집 결과 JSON 을 -OutFile 에 저장"),
    "Invoke-RestMethod": (r"Invoke-RestMethod -Uri \(\$Server\.TrimEnd\('/'\) \+ '/v1/tools/scans'\)", 1,
                          "-Upload 일 때 결과를 서버로 전송"),
    "Remove-Item": (r"if \(-not \$keepFile\) \{ Remove-Item -LiteralPath \$OutFile -Force \}", 1,
                    "업로드 후 자기가 만든 임시 결과 파일 삭제"),
    "Start-Process": (r"^Start-Process \$result\.url$", 1, "업로드 후 리포트 주소를 브라우저로 열기"),
}


def main() -> int:
    lines = SRC.read_text(encoding="utf-8-sig").splitlines()
    code = []
    in_block = False
    for i, line in enumerate(lines, 1):   # 주석은 검사하지 않는다
        s = line.strip()
        if s.startswith("<#"):
            in_block = True
        if in_block:
            if "#>" in s:
                in_block = False
            continue
        if s.startswith("#"):
            continue
        code.append((i, line))

    errors: list[str] = []
    used = {k: 0 for k in ALLOWED}
    for name in FORBIDDEN:
        pat = re.compile(rf"(?<![\w-]){re.escape(name)}(?![\w-])", re.IGNORECASE)
        for i, line in code:
            if not pat.search(line):
                continue
            allow = ALLOWED.get(name)
            if allow and re.search(allow[0], line.strip()):
                used[name] += 1
                continue
            errors.append(f"collector.ps1:{i}: '{name}' — {line.strip()[:120]}")
    for name, (_, n, why) in ALLOWED.items():
        if used[name] > n:
            errors.append(f"'{name}' 허용 {n}회({why})를 넘었습니다: {used[name]}회")

    if errors:
        print("읽기 전용 검사 실패:\n" + "\n".join(errors))
        return 1
    print("읽기 전용 검사 통과 — 시스템을 바꾸는 명령 없음. 허용된 예외:")
    for name, (_, n, why) in ALLOWED.items():
        print(f"  {name} ×{used[name]}: {why}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
