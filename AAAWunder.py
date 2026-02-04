import gdb
import os
import sys
import subprocess
import math
import json
import readline
import glob
import time

# ==========================================
# [Configuration & State]
# ==========================================
class WunderState:
    def __init__(self):
        self.target = None
        self.target_path = None
        self.config_hooks = []
        self.output_dir = "Wunder_Output"
        # [NEW] Advanced Config Variables
        self.config_args = ""
        self.config_input_file = None
        self.config_breakpoints = [] # list of addresses/symbols
        self.config_patches = []     # list of {'addr': addr, 'val': bytes}
        self.banner = """
    \033[1;36m██╗    ██╗██╗   ██╗███╗   ██╗██████╗ ███████╗██████╗ 
    ██║    ██║██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
    ██║ █╗ ██║██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
    ██║███╗██║██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
    ╚███╔███╔╝╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║
     ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝\033[0m
              \033[1;30m-- The Advanced CTF Analyzer --\033[0m
        """

    def print_banner(self):
        print(self.banner)
        # 상단에는 배너만 깔끔하게

state = WunderState()

# ==========================================
# [Global Helper: Autocomplete]
# ==========================================
class FileCompleter:
    """파일 목록 자동완성 로직"""
    def complete(self, text, state):
        if state == 0:
            # 입력된 텍스트가 없으면 전체 파일, 있으면 매칭되는 파일 검색
            if not text:
                self.matches = [f for f in os.listdir('.') if not f.startswith('.')]
            else:
                self.matches = glob.glob(text + '*')
        try:
            return self.matches[state]
        except IndexError:
            return None
        
def check_process_alive():
    try:
        return gdb.selected_inferior().pid > 0
    except:
        return False

def setup_global_features():
    """시스템 전체에 Readline(화살표 이동/탭 완성) 적용"""
    try:
        # 탭 키로 자동완성 연결
        readline.set_completer(FileCompleter().complete)
        readline.parse_and_bind('tab: complete')
        # 화살표 키 및 Home/End 키 활성화 (Linux/Mac 표준)
        readline.parse_and_bind('set editing-mode emacs')
    except Exception:
        # Windows 등 readline 지원이 없는 환경 예외 처리
        pass

# ==========================================
# [Helper Functions]
# ==========================================
def run_shell_cmd(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode()}"

# [FIX 1] 함수 이름 변경 (GDB 플러그인 충돌 방지)
def wunder_cls():
    os.system('cls' if os.name == 'nt' else 'clear')

def draw_file_grid(files):
    """파일 목록을 3열 그리드로 출력"""
    if not files:
        print("  (No files found)")
        return

    try:
        term_width = os.get_terminal_size().columns
    except:
        term_width = 100
    
    box_width = term_width - 4
    cols = 3 
    col_width = (box_width // cols) - 2
    rows = math.ceil(len(files) / cols)

    print("\033[1;37m┌" + "─" * (term_width - 2) + "┐\033[0m")
    
    for r in range(rows):
        line = "\033[1;37m│ \033[0m"
        for c in range(cols):
            idx = r * cols + c
            
            if idx < len(files):
                fname = files[idx]
                if "." not in fname:
                    color_code = "\033[1;32m" # Green
                else:
                    color_code = "\033[1;33m" # Yellow

                if len(fname) > col_width:
                    display_name = fname[:col_width-2] + ".."
                else:
                    display_name = fname
                
                padding = " " * (col_width - len(display_name))
                line += f"{color_code}{display_name}\033[0m{padding}  "
            else:
                line += " " * (col_width + 2)
        
        current_content_len = (col_width + 2) * cols
        line += " " * (term_width - 4 - current_content_len) + "\033[1;37m│\033[0m"
        print(line)

    print("\033[1;37m└" + "─" * (term_width - 2) + "┘\033[0m")

def save_to_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path

# [NEW] Massive Dumper Logic
def perform_massive_dump(prefix_dir):
    """모든 레지스터, 메모리, 어셈블리를 개별 파일로 덤프"""
    if not os.path.exists(prefix_dir): os.makedirs(prefix_dir)
    print(f"[*] Mass Dumping to: {prefix_dir}")

    # 1. Registers (Individual Files)
    reg_dir = os.path.join(prefix_dir, "registers")
    if not os.path.exists(reg_dir): os.makedirs(reg_dir)
    try:
        regs_output = gdb.execute("info registers", to_string=True)
        for line in regs_output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                reg_name = parts[0]
                save_to_file(os.path.join(reg_dir, f"{reg_name}.txt"), line)
    except Exception as e: print(f"    [!] Reg Dump Failed: {e}")

    # 2. Memory Segments (Stack & Text)
    mem_dir = os.path.join(prefix_dir, "memory")
    if not os.path.exists(mem_dir): os.makedirs(mem_dir)
    try:
        pid = gdb.selected_inferior().pid
        maps = run_shell_cmd(f"cat /proc/{pid}/maps").splitlines()
        for line in maps:
            # Dump Stack and Main Binary Code
            if "[stack]" in line or state.target in line:
                parts = line.split()
                range_str = parts[0]
                perm = parts[1]
                start, end = range_str.split('-')
                
                # 파일명 안전하게 생성
                name_clean = parts[-1].split('/')[-1].replace('[', '').replace(']', '')
                fname = f"{start}_{name_clean}_{perm}.bin"
                
                # GDB dump memory 명령어 사용
                try:
                    gdb.execute(f"dump memory {os.path.join(mem_dir, fname)} 0x{start} 0x{end}")
                except: pass
    except Exception as e: print(f"    [!] Mem Dump Failed: {e}")

    # 3. Assembly
    try:
        asm_path = os.path.join(prefix_dir, "full_assembly.asm")
        try:
            asm = gdb.execute("disassemble", to_string=True)
        except:
            pc = gdb.parse_and_eval("$pc")
            asm = gdb.execute(f"x/200i {pc}", to_string=True)
        save_to_file(asm_path, asm)
    except Exception as e: print(f"    [!] Asm Dump Failed: {e}")

# [NEW] Navigation Logic: Find Main in Stripped Binary
def auto_navigate_to_main(silent=False):
    """
    Entry Point로 이동 후, __libc_start_main의 1번째 인자를 분석하여 
    Main 함수 주소를 찾아내고 Breakpoint를 건다.
    """
    try:
        # 1. Entry Point 찾기
        out = gdb.execute("info files", to_string=True)
        entry_point = None
        for line in out.splitlines():
            if "Entry point" in line:
                entry_point = line.split(":")[-1].strip()
                break
        
        if not entry_point:
            if not silent: print("[!] Could not find Entry Point.")
            return False

        if not silent: print(f"[*] Entry Point Detected: {entry_point}. Warping...")
        
        # 2. Entry Point로 이동
        gdb.execute(f"tbreak *{entry_point}")
        gdb.execute("continue")
        
        # 3. Main 주소 역추적 (Heuristic)
        # _start 함수 내에서 __libc_start_main을 호출하는 패턴 분석
        # x64: mov rdi, MAIN; call __libc_start_main
        # x86: push MAIN; ...; call __libc_start_main
        
        # 현재 위치(_start)에서 50줄 정도 디스어셈블
        pc = gdb.parse_and_eval("$pc")
        asm = gdb.execute(f"x/50i {pc}", to_string=True)
        
        main_addr = None
        
        # 아주 단순한 파싱 (libc_start_main 직전의 push나 mov rdi를 찾음)
        lines = asm.splitlines()
        for i, line in enumerate(lines):
            if "__libc_start_main" in line:
                # call 명령어를 찾았다. 그 이전 명령어들을 스캔하여 main 주소 추정.
                # 보통 main 주소는 0x40... 이나 0x08... 로 시작하는 상수임.
                
                # 역순으로 탐색
                for prev_line in reversed(lines[:i]):
                    parts = prev_line.split()
                    # 0x... 형태의 주소값이 피연산자로 있는지 확인
                    for part in parts:
                        if part.startswith("0x"):
                            # 주소 후보 (예: 0x8048400)
                            candidate = part.strip(',').strip()
                            try:
                                # 주소 범위 체크 (너무 작거나 크면 제외)
                                val = int(candidate, 16)
                                if val > 0x400000 or (val > 0x8000000 and val < 0xf0000000):
                                    main_addr = candidate
                                    break
                            except: pass
                    if main_addr: break
            if main_addr: break
            
        if main_addr:
            if not silent: print(f"[*] Heuristic Success: 'main' seems to be at \033[1;32m{main_addr}\033[0m")
            gdb.execute(f"tbreak *{main_addr}")
            gdb.execute("continue")
            return True
        else:
            if not silent: print("[!] Could not pinpoint 'main'. Stayed at Entry Point.")
            return False # Entry Point에는 도달했음

    except Exception as e:
        if not silent: print(f"[!] Navigation Failed: {e}")
        return False

def save_chunks(path_prefix, content, chunk_size=2000):
    lines = content.splitlines()
    total_chunks = (len(lines) // chunk_size) + 1
    created_files = []
    
    for i in range(total_chunks):
        chunk = lines[i*chunk_size : (i+1)*chunk_size]
        if not chunk: continue
        file_path = f"{path_prefix}_part{i+1}.asm"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(chunk))
        created_files.append(file_path)
    return created_files

def get_register_state():
    try:
        # info registers는 아키텍처에 맞춰서 알아서 출력됨
        return gdb.execute("info registers", to_string=True)
    except:
        return "Register Info Failed"

def get_stack_dump(size=64):
    try:
        # 아키텍처 감지 (4바이트=32bit, 8바이트=64bit)
        ptr_size = int(gdb.parse_and_eval("sizeof(void*)"))
        
        if ptr_size == 4: # 32-bit Target
            sp_reg = "$esp"
            fmt = "wx" # 4-byte Word Hex
        else:             # 64-bit Target
            sp_reg = "$rsp"
            fmt = "gx" # 8-byte Giant Hex

        sp = gdb.parse_and_eval(sp_reg)
        return gdb.execute(f"x/{size}{fmt} {sp}", to_string=True)
    except Exception as e:
        return f"Stack Dump Failed: {e}"

# ==========================================
# [Menu 1] Select Target
# ==========================================
def select_target():
    print("\n\033[1;34m[*] Select Target Binary\033[0m")
    
    # 숨김 파일(.) 제외하고 필터링
    files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.startswith('.')]
    files.sort()
    
    draw_file_grid(files)
    
    print("\n\033[1;30m(Enter filename directly)\033[0m")
    selection = input("\033[4mWunder/Select\033[0m > ").strip()
    
    if os.path.isfile(selection):
        state.target = selection
        state.target_path = os.path.abspath(selection)
        
        print(f"\n[*] Loading \033[1;32m{selection}\033[0m into GDB...")
        gdb.execute(f"file {selection}")
        
        # 상세 정보 출력
        print("\n\033[1;34m[ Target Info ]\033[0m")
        file_info = run_shell_cmd(f"file {selection}")
        print(f"Info : {file_info}")
        
        input("\n[Target Set. Press Enter]")
    else:
        print("\n\033[1;31m[!] File not found.\033[0m")
        input()

# ==========================================
# [Menu 2] Analyze (The Bulldozer)
# ==========================================
def analyze_mode(silent=False):
    if not state.target: return
    if not os.path.exists(state.output_dir): os.makedirs(state.output_dir)
    
    use_input = False
    inp_file = state.config_input_file
    
    if not silent:
        print(f"\n\033[1;32m[*] Launching Bulldozer on {state.target}...\033[0m")
        # (입력 파일 설정 UI는 동일하므로 생략, 필요시 기존 코드 유지)
    
    if inp_file and os.path.exists(inp_file): use_input = True
    
    gdb.execute("set pagination off")
    gdb.execute("set disable-randomization on")
    gdb.execute("set confirm off")
    
    dump_folder = os.path.join(state.output_dir, f"dump_{int(time.time())}")
    
    try:
        # 1. 일단 프로세스 시작 (Loader 단계)
        run_cmd = f"starti < {inp_file}" if use_input else "starti"
        if not silent: print(f"[*] Executing '{run_cmd}'...")
        gdb.execute(run_cmd) 
        
        # 2. [핵심] Main 찾아서 이동
        if not silent: print("[*] Navigating to Main Code...")
        found_main = auto_navigate_to_main(silent=silent)
        
        # 3. 도착 지점에서 대규모 덤프
        if found_main:
            loc_name = "main"
        else:
            loc_name = "entry_point" # main 못 찾았으면 entry point라도 덤프
            
        if not silent: print(f"[*] Performing Massive Dump at {loc_name}...")
        perform_massive_dump(dump_folder + f"_{loc_name}")

        # 4. 끝까지 실행
        if not silent: print("[*] Running to end...")
        try: gdb.execute("continue")
        except: pass

        if not silent: print(f"\n\033[1;36m[+] Analysis Complete! Check {dump_folder}\033[0m")

    except Exception as e: print(f"\n\033[1;31m[!] Error: {e}\033[0m")
    if not silent: input("[Enter to return]")

# ==========================================
# [Menu 3] Advanced Analyze (The Tactician)
# ==========================================
def advanced_analyze():
    if not state.target:
        print("\n\033[1;31m[!] Error: No target selected.\033[0m"); input(); return
    
    while True:
        wunder_cls()
        state.print_banner()
        print(f"\n\033[1;34m[ Advanced Strategy : {state.target} ]\033[0m")
        
        print(f" [1] Set Arguments    : \033[1;33m{state.config_args if state.config_args else '(None)'}\033[0m")
        print(f" [2] Set Input File   : \033[1;33m{state.config_input_file if state.config_input_file else '(Keyboard)'}\033[0m")
        bp_str = ", ".join(state.config_breakpoints) if state.config_breakpoints else "(None)"
        print(f" [3] Add Breakpoint   : \033[1;36m{bp_str}\033[0m")
        patch_str = f"{len(state.config_patches)} patch(es)" if state.config_patches else "(None)"
        print(f" [4] Add Memory Patch : \033[1;31m{patch_str}\033[0m")
        hook_str = f"{len(state.config_hooks)} action(s)" if state.config_hooks else "(None)"
        print(f" [5] Add BP Action    : \033[1;35m{hook_str}\033[0m")
        
        print(f" [6] \033[1;35m[TASK EVA-01] Trace Diff & Hunt\033[0m")
        print(f" [7] \033[1;31m[TASK EVA-02] Input Mutation Tracker\033[0m")
        print(f" [8] \033[1;32m>>> RUN (Execute & Enter Live Session) <<<\033[0m")
        print(f" [A] \033[1;41m>>> THIRD IMPACT (Total Automation) <<<\033[0m")
        
        print(" [9] Clear All Config")
        print(" [0] Back to Main Menu")
        
        choice = input("\n\033[4mWunder/Advanced\033[0m > ").strip().upper()
        
        if choice == '1': state.config_args = input("Args: ")
        elif choice == '2':
            print("\n[Available Files]"); draw_file_grid([f for f in os.listdir('.') if os.path.isfile(f) and not f.startswith('.')])
            inp = input("Filename: ").strip()
            state.config_input_file = inp if inp and os.path.exists(inp) else None
        elif choice == '3':
            bp = input("Addr/Sym: ").strip()
            if bp: state.config_breakpoints.append("*" + bp if bp.startswith("0x") and not bp.startswith("*") else bp)
        elif choice == '4':
            a = input("Addr: ").strip(); v = input("Val(hex): ").strip()
            if a and v: state.config_patches.append({'addr': a, 'val': v})
        elif choice == '5':
            t = input("Target BP: ").strip(); c = input("Cmds: ").strip()
            if t and c: state.config_hooks.append({'point': t, 'cmds': c.replace(";", "\n")})

        elif choice == '6':
            print("\n[EVA-01] [1] Record Golden Path, [2] Hunt Divergence")
            sub = input("Mode > ").strip()
            if sub == '1': run_doppelganger(1)
            elif sub == '2': run_doppelganger(2)
            input("[Enter]")

        elif choice == '7':
            if not check_process_alive():
                print("\n[!] Start process with [8] RUN first."); input(); continue
            t = input("Target Address: ").strip()
            if t: run_eva_tracker(t)
            input("[Enter]")

        elif choice == '8':
            print(f"\n\033[1;32m[*] Executing Strategy...\033[0m")
            if state.config_args: gdb.execute(f"set args {state.config_args}")
            if state.config_patches:
                gdb.execute("starti")
                for p in state.config_patches:
                    try: gdb.selected_inferior().write_memory(int(p['addr'], 16), bytes.fromhex(p['val']))
                    except: pass
            
            gdb.execute("delete breakpoints")
            for bp in state.config_breakpoints: gdb.execute(f"break {bp}")
            for h in state.config_hooks:
                gdb.execute(f"break {h['point']}")
                gdb.execute(f"commands\n{h['cmds']}\nend")

            try:
                if state.config_patches: gdb.execute("continue")
                else:
                    run_cmd = f"run < {state.config_input_file}" if state.config_input_file else "run"
                    print(f"[*] Running: {run_cmd}")
                    gdb.execute(run_cmd)
            except Exception as e: print(f"[!] Log: {e}")

            while True:
                if not check_process_alive():
                    print("\n\033[1;31m[!] Process dead. Returning.\033[0m"); input(); break
                print(f"\n\033[1;44m[ Live Session: {state.target} ]\033[0m")
                print(" [1] GDB Shell  [2] Track Reg  [3] Track Mem")
                print(" [4] Continue   [0] Return")
                live = input("\n(Live) > ").strip()
                if live == '1':
                    while True:
                        c = input("(gdb) > "); 
                        if c in ['back','quit']: break
                        try: gdb.execute(c)
                        except: pass
                elif live == '2':
                    reg = input("Register: "); s = input("Steps: ")
                    if reg: run_tracer('reg', reg, int(s) if s.isdigit() else 1000)
                elif live == '3':
                    addr = input("Address: "); s = input("Steps: ")
                    if addr: run_tracer('mem', addr, int(s) if s.isdigit() else 1000)
                elif live == '4':
                    try: gdb.execute("continue")
                    except: pass
                elif live == '0': break

        # [A] THIRD IMPACT (수정됨)
        elif choice == 'A':
            print(f"\n\033[1;41m[*] INITIATING THIRD IMPACT SEQUENCE...\033[0m")
            
            # 입력 파일 보급
            if not state.config_input_file:
                print("\n\033[1;33m[!] WARNING: No Input File.\033[0m")
                print(" [1] Select File  [2] Create 'payload.txt'  [3] Empty")
                supply = input("Supply > ").strip()
                if supply == '1':
                    print("\n[Available Files]"); draw_file_grid([f for f in os.listdir('.') if os.path.isfile(f) and not f.startswith('.')])
                    f = input("Filename: ").strip()
                    if f and os.path.exists(f): state.config_input_file = f
                elif supply == '2':
                    with open("payload.txt", "w") as f: f.write("A"*100)
                    state.config_input_file = "payload.txt"
                    print("[+] Loaded 'payload.txt'.")
                elif supply != '3': continue 

            print(f"\n\033[1;41m[*] ALL SYSTEMS GO. IGNITION.\033[0m")
            time.sleep(1)

            # Phase 1: Bulldozer (Massive Dump)
            print(f"\n\033[1;33m[PHASE 1] Memory Structure & Massive Dump\033[0m")
            try: analyze_mode(silent=True)
            except Exception as e: print(f"[!] Phase 1 Failed: {e}")

            # Phase 2: Strategy Run
            print(f"\n\033[1;33m[PHASE 2] Strategy Execution (Hooks/BP)\033[0m")
            try:
                if state.config_args: gdb.execute(f"set args {state.config_args}")
                gdb.execute("delete breakpoints")
                for bp in state.config_breakpoints: gdb.execute(f"break {bp}")
                for h in state.config_hooks:
                    gdb.execute(f"break {h['point']}")
                    gdb.execute(f"commands\n{h['cmds']}\nend")
                
                run_cmd = f"run < {state.config_input_file}" if state.config_input_file else "run"
                print(f"[*] Running: {run_cmd}")
                gdb.execute(run_cmd)
                
                if check_process_alive():
                    print("[*] Paused. Performing Supplemental Dump...")
                    perform_massive_dump(os.path.join(state.output_dir, "dump_phase2_strategy"))
                    gdb.execute("kill")
            except Exception as e: print(f"[!] Phase 2 Failed: {e}")

            # Phase 3: EVA-01 (Golden Path)
            print(f"\n\033[1;33m[PHASE 3] EVA-01 Golden Path Recording\033[0m")
            try:
                # 1. 재시작
                run_cmd = f"starti < {state.config_input_file}" if state.config_input_file else "starti"
                gdb.execute(run_cmd)
                
                # 2. [핵심] 로더 탈출! Main이나 Entry Point로 이동
                print("[*] Warping to Main Code to avoid Loader trace...")
                auto_navigate_to_main(silent=True)
                
                # 3. 여기서부터 기록 시작
                run_doppelganger(1, silent=True)
            except Exception as e: print(f"[!] Phase 3 Failed: {e}")
            
            print(f"\n\033[1;41m[+] THIRD IMPACT COMPLETE. All Data Harvested.\033[0m")
            input("[Press Enter]")
        
        elif choice == '9':
            state.config_args = ""; state.config_input_file = None
            state.config_breakpoints = []; state.config_patches = []; state.config_hooks = []
            print("[*] Config Cleared."); input()
        elif choice == '0': break

# ==========================================
# [Tracer Logic]
# ==========================================
def run_tracer(target_type, target_val, max_steps=1000):
    if not check_process_alive():
        print("\n\033[1;31m[!] Process is not running.\033[0m")
        return

    # [FIX] 입력값 보정 로직 (User Input Sanitization)
    # 1. 파일명 생성을 위한 clean_name (기호 제거)
    clean_name = target_val.replace('*', '').replace('$', '').strip()
    
    # 2. GDB 전달을 위한 expr 생성 (기호 자동 부착)
    if target_type == 'reg':
        # $가 있으면 그대로, 없으면 붙임
        expr = target_val if target_val.startswith('$') else f"${target_val}"
    else: # mem
        # *가 있거나 0x로 시작하면 그대로, 아니면(변수명 등) 주소값 참조를 위해 * 붙임?
        # 상황: 사용자가 '0x8048000' 입력 -> '*0x8048000' (값 참조)
        # 상황: 사용자가 'flag' 입력 -> 'flag' (주소 혹은 값?) -> 보통 값 참조를 원함
        # 상황: 사용자가 '*0x8048000' 입력 -> 그대로
        expr = target_val if target_val.startswith('*') else f"*{target_val}"

    out_path = os.path.join(state.output_dir, f"trace_{clean_name}.jsonl")
    print(f"\n\033[1;36m[*] Tracing '{expr}' ({max_steps} steps) -> {out_path}\033[0m")
    
    logged_count = 0
    with open(out_path, "w", encoding="utf-8") as f:
        try:
            # 초기값 파싱
            val_obj = gdb.parse_and_eval(expr)
            prev_val = int(val_obj) # 여기서 에러나면 잘못된 타겟
        except Exception as e:
            print(f"\033[1;31m[!] Invalid Target '{expr}': {e}\033[0m")
            return

        for i in range(max_steps):
            try:
                frame = gdb.newest_frame()
                pc = frame.pc()
                try: asm = gdb.execute("x/i $pc", to_string=True).strip().split(':\t')[-1].strip()
                except: asm = "???"
                
                gdb.execute("stepi", to_string=True)
                
                # 현재값 파싱
                curr_val = int(gdb.parse_and_eval(expr))
                
                if curr_val != prev_val:
                    log_entry = {
                        "step": i, 
                        "pc": hex(pc), 
                        "asm": asm, 
                        "target": clean_name, 
                        "old": hex(prev_val), 
                        "new": hex(curr_val), 
                        "diff": hex(curr_val - prev_val)
                    }
                    f.write(json.dumps(log_entry) + "\n")
                    
                    # 변화 감지 시 화면 출력 (너무 빠르면 스킵 가능하나, 시각적 피드백 위해 유지)
                    print(f"\033[1;33m[Trace] {asm} | {log_entry['old']} -> {log_entry['new']}\033[0m")
                    
                    prev_val = curr_val
                    logged_count += 1
            except gdb.error:
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                break

    print(f"\n[+] Tracing Done. {logged_count} changes logged.")


# ==========================================
# [EVA-02: Input Mutation Tracker]
# ==========================================
def run_eva_tracker(addr_str):
    if not check_process_alive():
        print("\n\033[1;31m[!] Process is not running. Start it first with [RUN].\033[0m")
        return

    # 주소 파싱 (*0x... or 0x...)
    target = addr_str if addr_str.startswith("*") else f"*{addr_str}"
    clean_name = addr_str.replace('*', '').strip()
    out_path = os.path.join(state.output_dir, f"eva_mutation_{clean_name}.jsonl")
    
    print(f"\n\033[1;31m[*] Awakening EVA-02 (The Beast)...\033[0m")
    print(f"[*] Target Mutation Watch: \033[1;33m{target}\033[0m")
    print(f"[*] Logging to: {out_path}")
    
    # 하드웨어 워치포인트 설정 (Write 감지)
    try:
        # GDB의 watch 명령어는 파이썬 API보다 commands 연동이 쉬움
        gdb.execute(f"watch {target}")
    except Exception as e:
        print(f"[!] Failed to set watchpoint: {e}")
        return

    # 워치포인트 번호 가져오기 (가장 최근 것이므로 num 1, 2... 증가)
    # 안전하게 마지막 BP 번호를 가져옴
    bp_list = gdb.breakpoints()
    if not bp_list:
        print("[!] Error: Watchpoint not found.")
        return
    wp_num = bp_list[-1].number

    # 워치포인트에 'Commands' 주입 (핵심: Log & Continue)
    # 파이썬 코드를 GDB command 안에서 실행하려면 'python' 블록을 써야 함
    # 하지만 여기선 GDB printf가 빠르고 간편함
    
    # JSONL 포맷을 흉내내는 printf
    cmd_script = f"""commands {wp_num}
      silent
      printf "{{\\"pc\\": \\"%p\\", \\"new_val\\": \\"%d\\"}}\\n", $pc, {target}
      continue
    end"""
    
    gdb.execute(cmd_script)
    
    print(f"\n\033[1;31m[!] EVA-02 Launched! Monitoring mutations until death...\033[0m")
    print("[*] Press Ctrl+C manually if it loops forever.")
    
    # 로그 파일 준비 (헤더 없음, JSONL)
    # GDB output을 파일로 리다이렉트하는 건 복잡하므로, 
    # 여기서는 GDB의 로깅 기능을 켜서 파일로 저장하게 함
    gdb.execute("set logging file " + out_path)
    gdb.execute("set logging overwrite on")
    gdb.execute("set logging redirect on") # 화면 출력 끄고 파일로만
    gdb.execute("set logging on")
    
    try:
        gdb.execute("continue")
    except gdb.error as e:
        # 프로세스 종료/크래시 시 예외 발생 -> 정상 종료로 간주
        print(f"\n\033[1;32m[*] Target Neutralized (Process Died): {e}\033[0m")
    except KeyboardInterrupt:
        print("\n[*] EVA-02 Halted by Operator.")
    
    # 로깅 종료 및 복구
    gdb.execute("set logging off")
    gdb.execute("set logging redirect off")
    gdb.execute("delete breakpoints") # 워치포인트 제거
    
    print(f"[+] Mutation Log Saved: {out_path}")

def run_doppelganger(mode, silent=False):
    trace_file = os.path.join(state.output_dir, "golden_path.trace")
    
    if mode == 1: # Record Golden Path
        if not check_process_alive():
            if not silent: print("\n[!] Process dead."); return
            else: return # Silent fail

        if not silent: print(f"\n\033[1;32m[*] EVA-01: Recording Golden Path... (Max 50k steps)\033[0m")
        pcs = []
        try:
            for _ in range(50000):
                frame = gdb.newest_frame()
                pcs.append(frame.pc())
                gdb.execute("stepi", to_string=True)
        except: pass
        
        with open(trace_file, "w") as f:
            for p in pcs: f.write(f"{p}\n")
        if not silent: print(f"[+] EVA-01: Recorded {len(pcs)} steps.")

    elif mode == 2: # Hunt Divergence
        if not os.path.exists(trace_file):
            print("\n[!] No Golden Path found."); return
        if not check_process_alive():
            print("\n[!] Process dead."); return

        print(f"\n\033[1;31m[*] EVA-01: Hunting Divergence...\033[0m")
        with open(trace_file, "r") as f: golden_pcs = [int(line.strip()) for line in f.readlines()]
        
        idx = 0
        try:
            while idx < len(golden_pcs):
                curr_pc = gdb.newest_frame().pc()
                if curr_pc != golden_pcs[idx]:
                    print(f"\n\033[1;41m[!] DIVERGENCE at Step {idx}!\033[0m")
                    print(f"    Golden: {hex(golden_pcs[idx])} | Current: {hex(curr_pc)}")
                    gdb.execute("x/2i $pc")
                    return
                gdb.execute("stepi", to_string=True)
                idx += 1
                if idx % 1000 == 0: sys.stdout.write(f"\r[*] Steps: {idx}/{len(golden_pcs)}"); sys.stdout.flush()
        except: pass
        print("\n[*] Analysis finished without divergence or process died.")

# ==========================================
# [Menu 4 & 5] Tracking Implementation
# ==========================================
def tracking_memory():
    if not state.target: 
        print("\n[!] Select target first."); input(); return
        
    print(f"\n\033[1;34m[ Memory Tracker ]\033[0m")
    addr = input("Enter Address to track (e.g., 0x404040): ").strip()
    if not addr: return
    
    steps = input("Max Steps (default 1000): ").strip()
    steps = int(steps) if steps.isdigit() else 1000
    
    # 주소 포맷 보정 (0x... -> *0x... for eval)
    # 사용자가 그냥 주소만 입력하면 C스타일 포인터 역참조(*)를 붙여줌
    if not addr.startswith("*"):
        target = f"*{addr}" # 내용물을 본다는 뜻
    else:
        target = addr

    run_tracer('mem', target, steps)

def tracking_register():
    if not state.target: 
        print("\n[!] Select target first."); input(); return

    print(f"\n\033[1;34m[ Register Tracker ]\033[0m")
    reg = input("Enter Register to track (e.g., rax): ").strip()
    if not reg: return
    
    steps = input("Max Steps (default 1000): ").strip()
    steps = int(steps) if steps.isdigit() else 1000
    
    run_tracer('reg', reg, steps)

# ==========================================
# [Main Loop]
# ==========================================
def main_menu():
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    setup_global_features() # [NEW] 전역 기능 활성화
    while True:
        wunder_cls()
        state.print_banner()
        
        # 메뉴 표시
        print(" [1] select_target")
        print(" [2] analyze (Auto Dump & Diff)")
        print(" [3] advanced_analyze")
        print(" [4] tracking_memory")
        print(" [5] tracking_register")
        print(" [0] exit")
        
        print("\n" + "="*40)
        # 하단 Target 표시줄 강조
        if state.target:
            print(f" \033[1;32mTARGET >> {state.target}\033[0m")
        else:
            print(f" \033[1;30mTARGET >> (Not Selected)\033[0m")
        print("="*40)

        try:
            cmd = input("\n\033[4mWunder\033[0m >>> ").strip()
        except EOFError:
            break

        if cmd == '1':
            select_target()
        elif cmd == '2':
            analyze_mode()
        elif cmd == '3':
            advanced_analyze()
        elif cmd == '4':
            tracking_memory()
        elif cmd == '5':
            tracking_register()
        elif cmd == '0':
            gdb.execute("quit")
            sys.exit()

if __name__ == "__main__":
    main_menu()