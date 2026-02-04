# AAAWunder
Semi-automatic reversing solution tool


📘 AAAWunder: The God Killer - 작전 운용 교범
1. 시스템 개요 (Overview)
AAAWunder는 GDB 기반의 자동화 CTF/리버싱 분석 프레임워크입니다. 복잡한 GDB 명령어를 입력할 필요 없이, 메뉴 선택만으로 메모리 덤프, 실행 흐름 추적(Tracing), 변수 변이 감지, 안티 디버깅 우회를 수행합니다.

코드명: The God Killer

기반: Python 3 + GDB (User-Friendly Interface)

주요 기능:

Auto Navigation: 심볼이 없는(Stripped) 바이너리의 main 함수 자동 탐색.

Massive Dump: 레지스터, 스택, 힙, 어셈블리를 파일로 전량 추출.

EVA System: 실행 흐름 차분 분석(Doppelgänger) 및 데이터 변이 추적(Mutation Tracker).

Third Impact: 원버튼 완전 자동화 분석 시퀀스.

2. 출격 방법 (Launch)
터미널에서 GDB와 함께 스크립트를 로드하여 실행합니다.

Bash
# 기본 실행
gdb -x AAAWunder.py

# 또는 GDB 내부에서
(gdb) source AAAWunder.py
3. 전술 모드 상세 가이드
1️⃣ Select Target (타겟 설정)
분석할 바이너리 파일을 선택합니다.

[특징]: 화살표 키 이동 및 Tab 자동 완성이 지원됩니다.

2️⃣ Analyze: The Bulldozer (정찰 및 초토화)
적진(바이너리)에 강제 진입하여 지형(메모리)을 파악하고 대규모 데이터를 수집합니다.

작동 원리: Entry Point 진입 -> (자동 연산) -> main 함수 이동 -> 실행 -> 종료.

산출물 (Wunder_Output/):

dump_{time}_entry/: 진입점 시점의 모든 레지스터/메모리/어셈블리 파일.

dump_{time}_main/: Main 함수 진입 시점의 모든 데이터.

_maps.txt: 메모리 매핑 정보.

[전술적 가치]: 바이너리가 실행되자마자 죽어버리거나(Anti-Debug), 패킹되어 있을 때 **"죽기 전의 메모리"**를 확보하는 데 사용합니다.

3️⃣ Advanced Strategy: The Tactician (지휘 통제실)
이 툴의 핵심입니다. 전략을 설정하고, 특수 병기(EVA)를 투입합니다.

A. 전략 설정 (Configuration)
[1] Set Args: 실행 인자(Arguments) 설정.

[2] Set Input File: 표준 입력(stdin) 파일 설정. (Tab 완성 지원)

[3] Breakpoint: 주소(*0x...)나 심볼(main)에 BP 설정.

[4] Memory Patch: 특정 주소의 값을 변조 (예: 74 -> 90 NOP 패치).

[5] BP Action (Hooks): 특정 위치 도달 시 자동 명령 수행.

활용: ptrace 감지 함수에 걸고 return; continue를 입력하면 안티 디버깅을 무력화하고 지나갑니다.

B. 특수 병기 (EVA Series)
🟣 [6] TASK EVA-01: Doppelgänger (실행 흐름 사냥) "정상 입력과 공격 입력의 운명은 어디서 갈라지는가?"

Record Golden Path: 정상 입력값(예: "AAAA")으로 실행하여 **모든 명령어 주소(PC)**를 녹화합니다.

Hunt Divergence: 공격 입력값(예: "AAAB")으로 실행합니다. 툴이 Golden Path와 비교하다가 경로가 달라지는 순간(분기점) 즉시 멈춥니다.

용도: if (input == password) 같은 비교 구문을 1초 만에 찾아냄.

🔴 [7] DEPLOY EVA-02: Mutation Tracker (변이 추적) "내 입력값은 언제, 어떻게, 누구에 의해 바뀌는가?"

특정 메모리 주소(입력 버퍼 등)를 지정하면, 하드웨어 워치포인트를 설치합니다.

프로세스가 죽을 때까지, 해당 값이 바뀔 때마다(Write) 로그를 남기고 계속 실행합니다.

용도: 암호화 루틴, 압축 해제, 메모리 오염(Corruption) 과정 시각화.

C. 실행 및 자동화
🟢 [8] RUN (Live Session)

설정된 전략대로 실행합니다. BP나 Hook에 걸리면 **[Live Session]**이 열립니다.

Live Session 기능:

[1] GDB Shell: 수동 조작.

[2/3] Track Reg/Mem: 특정 레지스터나 메모리를 1,000 Step 정밀 추적.

[4] Continue: 계속 실행.

🔥 [A] THIRD IMPACT (Total Automation) "모든 것을 끝낸다." 버튼 하나로 다음 과정을 순차적으로 강제 집행합니다. 에러가 나도 멈추지 않습니다.

Phase 1: Bulldozer 모드 가동 (Entry/Main 대규모 덤프).

Phase 2: 설정된 Hook/Patch를 적용하여 Strategy 실행 (중간 덤프).

Phase 3: EVA-01을 가동하여 Golden Path 기록 확보.

[전술적 가치]: 대회 종료 직전, 혹은 분석 초기에 모든 데이터를 긁어모아두고 싶을 때 사용.

4. 데이터 분석 (Output Analysis)
모든 산출물은 Wunder_Output 폴더에 저장됩니다.

dump_.../registers/*.txt: 각 레지스터별 값 (비교 분석 용이).

dump_.../memory/*.bin: 스택, 힙, 코드 영역의 바이너리 덤프 (Hex Editor로 분석).

trace_....jsonl: 추적 로그. (Timeline 분석).

full_assembly.asm: 현재 시점의 전체 어셈블리 코드.

5. 함장(User)의 행동 수칙 (Protocol)
무조건 [A] Third Impact로 시작하십시오. 적의 정보를 최대한 긁어모으는 것이 우선입니다.

Stripped 바이너리라도 겁먹지 마십시오. Auto Navigation이 main을 찾아줍니다.

입력값이 어디서 튀는지 모를 땐 EVA-01을 쓰십시오. 정상 입력과 1바이트만 다른 입력을 넣고 돌리면, 비교 구문 앞에서 정확히 멈춥니다.

암호화 로직이 복잡하면 EVA-02를 붙이십시오. 입력값이 암호화되는 전 과정을 로그로 보여줍니다.

"AAAWunder와 함께라면, 불가능한 바이너리는 없습니다. 건승을 빕니다, 함장님."
