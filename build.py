"""collector.ps1 → 더블클릭용 MinerHunter-Collector.bat + SHA256SUMS.txt

    python build.py          → dist/

bat 은 앞부분(관리자 권한 재실행)만 배치 명령이고, '#PSSTART' 뒤는 collector.ps1 본문 그대로다.
PowerShell 이 자기 파일을 읽어 '#PSSTART' 뒤를 실행한다. 메모장으로 열어 전체 내용을 확인할 수 있다.

license.infralog.kr/tools 에서 받는 파일과 바이트 단위로 같도록 만든다 — 받은 파일의
SHA256 을 이 저장소 Release 의 SHA256SUMS.txt 와 비교해 같은 코드인지 확인할 수 있다.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"

BAT_HEAD = r"""@echo off
setlocal
chcp 65001 >nul
title MinerHunter Collector - infralog
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
set "MH_SELF=%~f0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s = Get-Content -LiteralPath $env:MH_SELF -Raw -Encoding UTF8; $m = '#' + 'PSSTART'; $i = $s.LastIndexOf($m); & ([scriptblock]::Create($s.Substring($i))) -Upload"
pause
exit /b

#PSSTART
"""


def build_bat(collector: Path) -> bytes:
    body = collector.read_text(encoding="utf-8-sig")
    # [scriptblock]::Create 안에서는 #requires 를 쓸 수 없다
    body = "\n".join(line for line in body.splitlines() if not line.lower().startswith("#requires"))
    # cmd.exe 는 BOM 없는 UTF-8 + CRLF 여야 앞부분을 바르게 읽는다
    return (BAT_HEAD + body + "\n").replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")


def main() -> int:
    DIST.mkdir(exist_ok=True)
    bat = build_bat(ROOT / "collector.ps1")
    out = DIST / "MinerHunter-Collector.bat"
    out.write_bytes(bat)
    ps1 = (ROOT / "collector.ps1").read_bytes()
    sums = (f"{hashlib.sha256(bat).hexdigest()}  MinerHunter-Collector.bat\n"
            f"{hashlib.sha256(ps1).hexdigest()}  collector.ps1\n")
    (DIST / "SHA256SUMS.txt").write_text(sums, encoding="utf-8", newline="\n")
    sys.stdout.write(sums)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
