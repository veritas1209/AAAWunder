import gdb
import os
import sys
import subprocess
import math
import json
import readline
import glob

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
def analyze_mode():
    if not state.target:
        print("\n\033[1;31m[!] Error: No target selected.\033[0m")
        input("[Press Enter]")
        return

    if not os.path.exists(state.output_dir):
        os.makedirs(state.output_dir)

    print(f"\n\033[1;32m[*] Starting Bulldozer Analysis on [{state.target}]...\033[0m")
    
    # [NEW] 입력 파일 설정
    print("\n[Input Configuration]")
    files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.startswith('.')]
    draw_file_grid(files)
    
    inp_file = input("Enter Input Filename (Enter for none): ").strip()
    use_input = False
    if inp_file and os.path.exists(inp_file):
        use_input = True
        print(f"[*] Input set to: {inp_file}")
    else:
        print("[*] No input file. Running normally.")

    # GDB 설정
    gdb.execute("set pagination off")
    gdb.execute("set disable-randomization on")
    gdb.execute("set confirm off")

    base_name = os.path.join(state.output_dir, state.target)
    
    try:
        # 1. starti (입력 파일이 있으면 리다이렉션 포함)
        run_cmd = f"starti < {inp_file}" if use_input else "starti"
        print(f"[*] Executing '{run_cmd}'...")
        gdb.execute(run_cmd)
        
        # 2. Memory Map
        print("[*] Dumping Memory Mappings...")
        pid = gdb.selected_inferior().pid
        mappings = run_shell_cmd(f"cat /proc/{pid}/maps")
        save_to_file(f"{base_name}_maps.txt", mappings)
        
        # 3. Main 진입 시도
        try:
            main_addr = gdb.parse_and_eval("main").address
            print(f"[*] 'main' found at {hex(main_addr)}. Continuing to main...")
            gdb.Breakpoint("main", temporary=True)
            gdb.execute("continue")
        except Exception as e:
            # [FIX] 색상 변경 Red -> Yellow
            print(f"\033[1;33m[!] Could not find 'main' symbol. Continuing from Entry Point.\033[0m")

        # 4. 초기 상태 덤프
        print("[*] Snapshotting Initial State (Regs & Stack)...")
        initial_regs = get_register_state()
        initial_stack = get_stack_dump(64)
        
        # 5. 어셈블리 덤프
        print("[*] Dumping Assembly Code...")
        try:
            # 현재 PC 기준으로 함수 범위가 잡히면 덤프, 아니면 PC 주변 100줄
            asm_content = gdb.execute("disassemble", to_string=True)
            save_chunks(f"{base_name}_wunder", asm_content, chunk_size=2000)
        except:
            # 심볼이 없어서 disassemble이 실패할 경우, x/i로 직접 긁어옴 (fallback)
            print("    [!] Disassembly failed (No symbol). Dumping raw instructions...")
            pc = gdb.parse_and_eval("$pc")
            raw_asm = gdb.execute(f"x/100i {pc}", to_string=True) # 100줄만
            save_to_file(f"{base_name}_raw.asm", raw_asm)

        # 6. 끝까지 실행
        print("[*] Running to end (continue)...")
        end_state = "Unknown"
        try:
            gdb.execute("continue")
            end_state = "Paused (Breakpoint or Step)"
        except gdb.error as e:
            msg = str(e)
            if "exited normally" in msg:
                end_state = "Exited Normally (0)"
            elif "exited with code" in msg:
                end_state = f"Exited with Code {msg}"
            else:
                end_state = f"Crashed/Stopped: {msg}"
            print(f"    [!] Program state changed: {end_state}")

        # 7. 종료 상태 덤프
        print("[*] Snapshotting Final State...")
        try:
            final_regs = get_register_state()
            final_stack = get_stack_dump(64)
        except:
            final_regs = "Process Exited - No Register Info"
            final_stack = "Process Exited - No Stack Info"

        report = f"""[AAAWunder Analysis Report]
Target: {state.target}
Input File: {inp_file if use_input else "None"}
End State: {end_state}

[Register Change]
--- BEFORE ---
{initial_regs}
--- AFTER ---
{final_regs}

[Stack Change]
--- BEFORE ---
{initial_stack}
--- AFTER ---
{final_stack}
"""
        report_path = f"{base_name}_report.txt"
        save_to_file(report_path, report)
        print(f"\n\033[1;36m[+] Analysis Complete! Report saved to: {report_path}\033[0m")

    except Exception as e:
        print(f"\n\033[1;31m[!] Critical Error: {e}\033[0m")
    
    input("[Press Enter to return]")

# ==========================================
# [Menu 3] Advanced Analyze (The Tactician)
# ==========================================
def advanced_analyze():
    if not state.target:
        print("\n\033[1;31m[!] Error: No target selected.\033[0m")
        input("[Press Enter]")
        return
    
    while True:
        wunder_cls()
        state.print_banner()
        print(f"\n\033[1;34m[ Advanced Strategy : {state.target} ]\033[0m")
        
        # [Config Menu]
        print(f" [1] Set Arguments    : \033[1;33m{state.config_args if state.config_args else '(None)'}\033[0m")
        print(f" [2] Set Input File   : \033[1;33m{state.config_input_file if state.config_input_file else '(Keyboard)'}\033[0m")
        
        bp_str = ", ".join(state.config_breakpoints) if state.config_breakpoints else "(None)"
        print(f" [3] Add Breakpoint   : \033[1;36m{bp_str}\033[0m")
        
        patch_str = f"{len(state.config_patches)} patch(es)" if state.config_patches else "(None)"
        print(f" [4] Add Memory Patch : \033[1;31m{patch_str}\033[0m")

        hook_cnt = len(state.config_hooks)
        if hook_cnt > 0:
            hook_str = f"{hook_cnt} action(s)"
            for h in state.config_hooks:
                hook_str += f"\n      └─ On '{h['point']}': {h['cmds'].replace(chr(10), '; ')[:30]}..."
        else:
            hook_str = "(None)"
        print(f" [5] Add BP Action    : \033[1;35m{hook_str}\033[0m")
        
        print("\n [6] \033[1;32m>>> RUN (Execute & Enter Live Session) <<<\033[0m")
        print(" [9] Clear All Config")
        print(" [0] Back to Main Menu")
        
        choice = input("\n\033[4mWunder/Advanced\033[0m > ").strip()
        
        # --- Config Handling ---
        if choice == '1':
            state.config_args = input("Enter Arguments: ")
        
        elif choice == '2':
            print("\n[ Available Files ]")
            files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.startswith('.')]
            draw_file_grid(files)
            inp = input("Enter Input Filename (or Enter to reset): ").strip()
            if inp and os.path.exists(inp): state.config_input_file = inp
            else: state.config_input_file = None
        
        elif choice == '3':
            bp = input("Enter Address/Symbol (e.g. *0x8048000, main): ").strip()
            if bp:
                if bp.startswith("0x") and not bp.startswith("*"): bp = "*" + bp
                state.config_breakpoints.append(bp)
        
        elif choice == '4':
            p_addr = input("Address (hex): ").strip()
            p_val = input("Value (hex bytes): ").strip()
            if p_addr and p_val: state.config_patches.append({'addr': p_addr, 'val': p_val})

        elif choice == '5':
            target = input("Target BP: ").strip()
            cmds = input("Cmds (e.g. finish; set $rax=0; c): ").strip()
            if target and cmds:
                state.config_hooks.append({'point': target, 'cmds': cmds.replace(";", "\n")})

        elif choice == '9':
            state.config_args = ""; state.config_input_file = None
            state.config_breakpoints = []; state.config_patches = []; state.config_hooks = []
            print("[*] Config Cleared."); input()

        elif choice == '0':
            break

        # --- Execution Logic ---
        elif choice == '6':
            print(f"\n\033[1;32m[*] Executing Reinforced Strategy...\033[0m")
            
            # 1. Apply Args
            if state.config_args: gdb.execute(f"set args {state.config_args}")
            
            # 2. Apply Patches (requires starti)
            need_starti = bool(state.config_patches)
            if need_starti:
                print("[*] Applying Patches (starti)...")
                gdb.execute("starti")
                for p in state.config_patches:
                    try:
                        gdb.selected_inferior().write_memory(int(p['addr'], 16), bytes.fromhex(p['val']))
                        print(f"    -> Patched {p['addr']}")
                    except Exception as e: print(f"    [!] Patch Fail: {e}")
            
            # 3. Setup Breakpoints & Hooks
            gdb.execute("delete breakpoints")
            for bp in state.config_breakpoints: gdb.execute(f"break {bp}")
            for h in state.config_hooks:
                gdb.execute(f"break {h['point']}")
                gdb.execute(f"commands\n{h['cmds']}\nend")
                print(f"    -> Hook set on '{h['point']}'")

            # 4. Run Execution
            try:
                if need_starti:
                    print("[*] Continuing...")
                    gdb.execute("continue")
                else:
                    run_cmd = f"run < {state.config_input_file}" if state.config_input_file else "run"
                    print(f"[*] Running: {run_cmd}")
                    gdb.execute(run_cmd)
            except Exception as e:
                print(f"[!] Execution State: {e}")

            # ==========================================
            # [Live Session Loop]
            # ==========================================
            while True:
                # Check process state
                try:
                    if not gdb.selected_inferior().pid:
                        print("\n\033[1;31m[!] Process is dead. Returning to Config.\033[0m")
                        input(); break
                except: break

                print(f"\n\033[1;44m[ Live Session: {state.target} ]\033[0m")
                print(" [1] GDB Shell (Inspect State)")
                print(" [2] Track Register (JSONL)")
                print(" [3] Track Memory (JSONL)")
                print(" [4] Continue Execution")
                print(" [0] Stop & Return to Config")
                
                live_cmd = input("\n\033[1;33m(Live) > \033[0m").strip()
                
                if live_cmd == '1': # GDB Shell
                    print("\n\033[1;36m[ Entering GDB Shell. Type 'back' to return. ]\033[0m")
                    while True:
                        try:
                            c = input("\033[1;36m(gdb-shell)\033[0m > ").strip()
                            if c.lower() in ['back', 'exit', 'quit']: break
                            if not c: continue
                            gdb.execute(c)
                        except Exception as e: print(f"Error: {e}")

                elif live_cmd == '2': # Track Reg
                    # [FIX] 입력 보정: 사용자가 $를 넣든 말든 그대로 넘김 (run_tracer가 처리)
                    reg = input("Register (e.g. rax or $eip): ").strip()
                    steps = input("Max Steps (1000): ").strip()
                    if reg: 
                        run_tracer('reg', reg, int(steps) if steps.isdigit() else 1000)

                elif live_cmd == '3': # Track Mem
                    # [FIX] 입력 보정: 사용자가 주소만 넣어도 됨
                    addr = input("Address (e.g. 0x4000 or *0x4000): ").strip()
                    steps = input("Max Steps (1000): ").strip()
                    if addr:
                        run_tracer('mem', addr, int(steps) if steps.isdigit() else 1000)

                elif live_cmd == '4': # Continue
                    print("[*] Continuing..."); 
                    try: gdb.execute("continue")
                    except Exception as e: print(f"[!] Stopped: {e}")

                elif live_cmd == '0': # Stop
                    print("[*] Returning to Config.")
                    break

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