import gdb
import os
import sys
import subprocess
import math
import json

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
# [Menu 3] Advanced Analyze (Reinforced)
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
        
        # 설정 상태 표시
        print(f" [1] Set Arguments    : \033[1;33m{state.config_args if state.config_args else '(None)'}\033[0m")
        print(f" [2] Set Input File   : \033[1;33m{state.config_input_file if state.config_input_file else '(Keyboard)'}\033[0m")
        
        bp_str = ", ".join(state.config_breakpoints) if state.config_breakpoints else "(None)"
        print(f" [3] Add Breakpoint   : \033[1;36m{bp_str}\033[0m")
        
        patch_str = f"{len(state.config_patches)} patch(es)" if state.config_patches else "(None)"
        print(f" [4] Add Memory Patch : \033[1;31m{patch_str}\033[0m")

        # [NEW] Hook 표시
        if state.config_hooks:
            hook_str = f"{len(state.config_hooks)} action(s)"
            # 상세 내용 살짝 보여주기
            for i, h in enumerate(state.config_hooks):
                hook_str += f"\n      └─ On '{h['point']}': {h['cmds'][:30]}..."
        else:
            hook_str = "(None)"
        print(f" [5] Add BP Action    : \033[1;35m{hook_str}\033[0m")
        
        print("\n [6] \033[1;32m>>> RUN (Execute Strategy) <<<\033[0m")
        print(" [7] \033[1;36mOpen GDB Shell (Inspect State)\033[0m")
        print(" [9] Clear All Config")
        print(" [0] Back to Main Menu")
        
        choice = input("\n\033[4mWunder/Advanced\033[0m > ").strip()
        
        if choice == '1':
            state.config_args = input("Enter Arguments: ")
        
        elif choice == '2':
            # 파일 목록 보여주고 선택
            print("\n[ Available Files ]")
            files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.startswith('.')]
            files.sort()
            draw_file_grid(files)
            inp = input("Enter Input Filename (or Enter to reset): ").strip()
            if inp and os.path.exists(inp):
                state.config_input_file = inp
            else:
                state.config_input_file = None
        
        elif choice == '3':
            bp = input("Enter Address or Symbol (e.g., 0x8048000 or main): ").strip()
            if bp:
                # 16진수 주소(0x...)로 시작하는데 *가 없으면 자동으로 붙여줌
                if bp.startswith("0x") and not bp.startswith("*"):
                    bp = "*" + bp
                state.config_breakpoints.append(bp)
        
        elif choice == '4':
            print("\n[!] Memory Patch (Applies after starti)")
            p_addr = input("Address (hex): ").strip()
            p_val = input("Value (hex bytes, e.g., 9090): ").strip()
            if p_addr and p_val:
                state.config_patches.append({'addr': p_addr, 'val': p_val})

        # [NEW] Hook 설정 메뉴
        elif choice == '5':
            print("\n\033[1;35m[ Automate Actions on Breakpoint ]\033[0m")
            print("Usage: When 'Target' is hit, execute 'Commands' automatically.")
            print("Commands: Use ';' to separate multiple GDB commands.")
            print("Example: finish; set $rax=0; continue")
            
            target = input("Target BP (e.g., time): ").strip()
            cmds = input("Commands (e.g., finish; set $rax=0; c): ").strip()
            
            if target and cmds:
                # 세미콜론을 개행 문자로 변환 (GDB commands 문법 맞춤)
                formatted_cmds = cmds.replace(";", "\n")
                state.config_hooks.append({'point': target, 'cmds': formatted_cmds})

        elif choice == '6':
            # === [EXECUTION LOGIC] ===
            print(f"\n\033[1;32m[*] Executing Reinforced Strategy...\033[0m")
            
            # 1. Args 설정
            if state.config_args:
                gdb.execute(f"set args {state.config_args}")
            
            # 2. Patch 적용 로직 (starti 필요)
            need_starti = bool(state.config_patches)
            
            if need_starti:
                print("[*] Starting process to apply patches...")
                gdb.execute("starti")
                for p in state.config_patches:
                    try:
                        addr_int = int(p['addr'], 16)
                        byte_data = bytes.fromhex(p['val'])
                        gdb.selected_inferior().write_memory(addr_int, byte_data)
                        print(f"    -> Patched {p['addr']} with {p['val']}")
                    except Exception as e:
                        print(f"    [!] Patch Failed: {e}")
            else:
                # Patch 없으면 그냥 Breakpoint 걸고 Run할 준비
                pass

            # 3. Breakpoint & Hook 설정
            print("[*] Setting Breakpoints & Actions...")
            gdb.execute("delete breakpoints") # 기존 BP 초기화
            
            # 3-1. 일반 Breakpoint
            for bp in state.config_breakpoints:
                gdb.execute(f"break {bp}")
            
            # 3-2. Hook (Action) Breakpoint
            # GDB의 commands 기능을 파이썬으로 주입
            for hook in state.config_hooks:
                # 1) 브레이크포인트 생성
                b = gdb.Breakpoint(hook['point'])
                # 2) 해당 브레이크포인트 번호에 명령어(commands) 주입
                # 주의: commands {num} \n cmd1 \n cmd2 \n end 구조여야 함
                cmd_block = f"commands {b.number}\n{hook['cmds']}\nend"
                gdb.execute(cmd_block)
                print(f"    -> Hook set on '{hook['point']}' (BP #{b.number})")

            # 4. 실행 (Run or Continue)
            if need_starti:
                print("[*] Continuing...")
                gdb.execute("continue")
            else:
                run_cmd = "run"
                if state.config_input_file:
                    run_cmd += f" < {state.config_input_file}"
                print(f"[*] Running: {run_cmd}")
                try:
                    gdb.execute(run_cmd)
                except Exception as e:
                    print(f"[!] Execution finished: {e}")

            input("\n[Execution Paused. Press Enter to return]")

        elif choice == '7':
            print("\n\033[1;36m[ Entering GDB Shell ]\033[0m")
            print("Type GDB commands directly. Type 'back' or 'exit' to return to menu.")
            
            while True:
                try:
                    gdb_cmd = input("\033[1;36m(gdb-shell)\033[0m > ").strip()
                    if gdb_cmd.lower() in ['back', 'exit', 'quit']:
                        break
                    if not gdb_cmd: continue
                    
                    # GDB 명령어 실행 및 결과 출력
                    gdb.execute(gdb_cmd)
                    
                except gdb.error as e:
                    print(f"Error: {e}")
                except KeyboardInterrupt:
                    print("\n[!] Use 'back' to return.")

        elif choice == '9':
            state.config_args = ""
            state.config_input_file = None
            state.config_breakpoints = []
            state.config_patches = []
            state.config_hooks = [] # Hook 초기화
            print("[*] Config Cleared.")
            input()

        elif choice == '0':
            break

# ==========================================
# [Helper: Tracer Logic]
# ==========================================
def run_tracer(target_type, target_val, max_steps=1000):
    """
    target_type: 'reg' or 'mem'
    target_val: 'rax' or '0x401000' (string)
    """
    # 1. 프로세스 실행 여부 확인
    try:
        gdb.selected_inferior()
    except:
        print("\n\033[1;31m[!] Error: Process is not running. Start it with option [2] or [3] first.\033[0m")
        input()
        return

    # 출력 파일 설정
    clean_name = target_val.replace('*', '').replace('$', '')
    out_path = os.path.join(state.output_dir, f"trace_{clean_name}.jsonl")
    
    print(f"\n\033[1;36m[*] Start Tracing '{target_val}' for {max_steps} steps...\033[0m")
    print(f"    Output -> {out_path}")
    
    logged_count = 0
    
    with open(out_path, "w", encoding="utf-8") as f:
        # 초기 값 로드
        prev_val = None
        try:
            if target_type == 'reg':
                prev_val = gdb.parse_and_eval(f"${target_val}")
            else: # mem
                # 포인터면 *addr, 아니면 그냥 addr
                expr = target_val if target_val.startswith('*') else f"*{target_val}"
                prev_val = gdb.parse_and_eval(expr)
            prev_val = int(prev_val) # 정수형 변환
        except Exception as e:
            print(f"\033[1;31m[!] Invalid Target: {e}\033[0m")
            input()
            return

        # [Tracing Loop]
        for i in range(max_steps):
            try:
                # 1. 현재 PC와 명령어 가져오기
                frame = gdb.newest_frame()
                pc = frame.pc()
                # 현재 어셈블리 가져오기 (x/i $pc)
                asm = gdb.execute("x/i $pc", to_string=True).strip().split(':\t')[-1].strip()
                
                # 2. 한 스텝 진행 (stepi)
                gdb.execute("stepi", to_string=True)
                
                # 3. 값 변화 체크
                curr_val = 0
                if target_type == 'reg':
                    curr_val = int(gdb.parse_and_eval(f"${target_val}"))
                else:
                    expr = target_val if target_val.startswith('*') else f"*{target_val}"
                    curr_val = int(gdb.parse_and_eval(expr))
                
                # 값이 변했거나, 루프의 첫 시작(Context)이면 기록? -> 변했을 때만 기록하자 (토큰 절약)
                if curr_val != prev_val:
                    log_entry = {
                        "step": i,
                        "pc": hex(pc),
                        "asm": asm,
                        "target": target_val,
                        "old": hex(prev_val),
                        "new": hex(curr_val),
                        "diff": hex(curr_val - prev_val) # 변화량 (암호화 분석에 꿀)
                    }
                    f.write(json.dumps(log_entry) + "\n")
                    prev_val = curr_val
                    logged_count += 1
                    
                    # 화면엔 간략히 표시
                    print(f"\033[1;33m[Trace] {asm} | {log_entry['old']} -> {log_entry['new']}\033[0m")

            except gdb.error:
                print("\n[!] Process stopped/finished.")
                break
            except Exception as e:
                print(f"\n[!] Error during trace: {e}")
                break

    print(f"\n\033[1;32m[+] Tracing Done. {logged_count} changes logged.\033[0m")
    input("[Press Enter to return]")


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