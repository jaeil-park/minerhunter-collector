# MinerHunter Collector

[infralog 도구](https://infralog.kr/tools/)의 PC 보안 점검(MinerHunter)에서 쓰는 **수집 프로그램**의 전체 소스입니다.

이 프로그램은 **아무것도 판정하지 않고, 아무것도 바꾸지 않습니다.** PC 의 프로세스·서비스·자동 실행 같은 정보를
있는 그대로 모아 JSON 으로 저장하고, 원할 때만 점검 서버로 보냅니다. 무엇이 위험한지는 서버가 판정합니다.
판정 규칙은 이 저장소에 없습니다 — 공개되면 악성코드가 피해 가도록 바뀔 수 있기 때문입니다.

## 왜 공개하나요

PC 정보를 읽는 프로그램은 믿을 수 있어야 합니다. 이 저장소에서는 누구나:

- 수집기가 **무엇을 읽는지** 코드로 확인할 수 있고
- 수집기에 **PC 를 바꾸는 명령이 없다는 것**을 자동 검사([`verify.py`](verify.py))로 확인할 수 있고
- 웹에서 받은 파일이 **이 소스로 만든 파일과 같은지** 해시로 확인할 수 있습니다

## 무엇을 읽나요

| 항목 | 내용 |
|---|---|
| 시스템 | Windows 버전, 제조사·모델, 메모리 크기, 마지막 부팅 시각, 메모리 커밋 사용량·CPU 사용률 |
| 이벤트 기록 | 최근 30일 시스템 로그 중 메모리 고갈 진단(2004), 오류 팝업, 서비스 시작 실패(7000) |
| 프로세스 | 실행 중인 프로그램의 이름·경로·명령줄·부모·메모리·시작 시각 |
| 서비스·드라이버 | 이름·실행 경로·상태, 서비스 DLL 경로 |
| 예약 작업 | 경로·이름·작성자·실행 명령 |
| 자동 실행 | Run/RunOnce 레지스트리, 시작프로그램 폴더(스크립트는 200KB 미만만 내용 포함), WMI 이벤트 구독, IFEO 디버거, Winlogon |
| Defender | 실시간 보호 상태, 검사 예외(프로세스·경로·확장자), 설치된 백신 이름, 최근 탐지 10건 |
| 파일 목록 | ProgramData·공용 폴더·사용자 AppData(Roaming, Temp) 일부 깊이까지의 **파일 이름·크기·만든 시각** (내용은 읽지 않음). cmd·powershell 과 크기가 같은 exe 만 해시 계산 |
| 네트워크 | DNS 캐시, 연결 중인 TCP 주소·포트, hosts 파일 |
| 서명 | 위에서 나온 실행 파일의 디지털 서명 여부 |

계정 비밀번호, 브라우저 기록·쿠키, 문서·사진 같은 파일 내용은 읽지 않습니다.

## PC 를 바꾸나요

바꾸지 않습니다. 이 저장소의 CI 는 매번 [`verify.py`](verify.py)로 수집기에서 프로세스 종료·레지스트리/서비스/예약작업/Defender
변경·파일 삭제·원격 코드 실행 명령을 찾고, 아래 네 가지 용도 외에 하나라도 있으면 빌드를 실패시킵니다.

| 허용된 동작 | 용도 |
|---|---|
| 파일 쓰기 1곳 | 수집 결과 JSON 저장 |
| 서버 전송 1곳 | `-Upload` 일 때만, 웹에서 받은 1회용 연결 코드와 함께 |
| 파일 삭제 1곳 | 업로드 뒤 **자기가 만든** 임시 결과 파일 삭제 |
| 브라우저 열기 1곳 | 업로드 뒤 리포트 주소 열기 |

## 사용법

일반 사용자는 [infralog.kr/tools](https://infralog.kr/tools/) 안내대로 로그인 → `MinerHunter-Collector.bat` 받기 → 더블클릭하면 됩니다.

직접 실행하려면 (관리자 PowerShell):

```powershell
# 수집만 (서버로 보내지 않음)
powershell -ExecutionPolicy Bypass -File .\collector.ps1 -OutFile .\collect.json

# 수집 후 업로드 (웹에서 받은 연결 코드 필요)
powershell -ExecutionPolicy Bypass -File .\collector.ps1 -Upload -Code ABCD-EFGH
```

서버는 받은 수집 자료를 판정한 뒤 바로 버리고 판정 결과만 30일 보관합니다
([개인정보처리방침](https://license.infralog.kr/legal/privacy)).

## 받은 파일 확인하기

[Releases](../../releases) 의 `SHA256SUMS.txt` 는 GitHub Actions 가 이 저장소 소스로 직접 빌드한 값입니다.
웹에서 받은 파일의 해시가 같으면 같은 코드입니다.

```powershell
Get-FileHash .\MinerHunter-Collector.bat -Algorithm SHA256
```

`MinerHunter-Collector.bat` 은 앞 13줄(관리자 권한으로 다시 실행)만 배치 명령이고, `#PSSTART` 아래는 `collector.ps1` 과 같은 내용입니다.
메모장으로 열어 볼 수 있습니다.

## 빌드

```bash
python verify.py   # 읽기 전용 검사
python build.py    # dist/MinerHunter-Collector.bat + SHA256SUMS.txt
```

## 요구 사항

Windows 10·11, Windows PowerShell 5.1(기본 내장). 다른 사용자 프로그램 정보와 Defender 예외를 읽으려면 관리자 권한이 필요합니다.

## 라이선스

MIT — [LICENSE](LICENSE). 문의: jaeilpark82@gmail.com (해우소)
