// c2paview.dll - "Content Credentials" tab for Explorer's file Properties dialog.
//
// Deliberately thin: this DLL is loaded inside explorer.exe, so it does no parsing of
// the file at all. It launches c2paview-helper.exe (Rust, c2pa-rs) as a low-integrity,
// job-limited child process with a timeout, reads a simple line protocol back, and
// draws it. A malformed or hostile file can crash the helper; it cannot crash Explorer.
//
// Registration is done by scripts/Install-C2paViewTab.ps1 (per-user, HKCU), not here.

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <sddl.h>
#include <aclapi.h>
#include <cstdlib>
#include <new>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include "resource.h"

// {5E9746CC-4EDB-460C-AA85-D2718CABC7FC}
static const CLSID CLSID_C2paViewPropSheet =
    { 0x5E9746CC, 0x4EDB, 0x460C, { 0xAA, 0x85, 0xD2, 0x71, 0x8C, 0xAB, 0xC7, 0xFC } };

static HINSTANCE g_hInst = nullptr;
static std::atomic<long> g_cObj{ 0 };      // live COM objects
static std::atomic<long> g_cLock{ 0 };     // IClassFactory::LockServer
static std::atomic<long> g_cThreads{ 0 };  // worker threads still executing our code

static const UINT  WM_APP_RESULT      = WM_APP + 1;
static const UINT  IDT_TIMEOUT        = 1;
static const DWORD HELPER_TIMEOUT_MS  = 45000;
static const DWORD MAX_OUTPUT_BYTES   = 16 * 1024 * 1024;
static const SIZE_T HELPER_MEMORY_LIMIT = (SIZE_T)2048 * 1024 * 1024;

// ------------------------------------------------------------------ small helpers

static std::wstring Utf8ToWide(const char* p, size_t n)
{
    if (n == 0) return {};
    int cch = MultiByteToWideChar(CP_UTF8, 0, p, (int)n, nullptr, 0);
    if (cch <= 0) return {};
    std::wstring w((size_t)cch, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, p, (int)n, &w[0], cch);
    return w;
}

static std::wstring ModuleDir()
{
    std::wstring path(32768, L'\0');
    DWORD n = GetModuleFileNameW(g_hInst, &path[0], (DWORD)path.size());
    if (n == 0 || n >= path.size()) return {};
    path.resize(n);
    size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash);
}

// Prefix very long paths so the helper can open them (Rust std passes the path through).
static std::wstring LongPathSafe(const std::wstring& p)
{
    if (p.size() >= 248 && p.compare(0, 2, L"\\\\") != 0) return L"\\\\?\\" + p;
    if (p.size() >= 248 && p.compare(0, 4, L"\\\\?\\") != 0 && p.compare(0, 2, L"\\\\") == 0) return L"\\\\?\\UNC\\" + p.substr(2);
    return p;
}

// ------------------------------------------------------------------ helper output model

struct Node { int depth; bool expanded; std::wstring text; };

struct Model
{
    std::wstring state, head, text, json;
    std::vector<Node> nodes;
    bool complete = false;   // saw END
};

static void ParseOutput(const std::string& raw, Model& m)
{
    size_t pos = 0;
    std::wstring textAcc;
    while (pos < raw.size()) {
        size_t nl = raw.find('\n', pos);
        if (nl == std::string::npos) nl = raw.size();
        std::string line = raw.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        std::vector<std::string> f;
        size_t s = 0;
        while (true) {
            size_t t = line.find('\t', s);
            if (t == std::string::npos) { f.push_back(line.substr(s)); break; }
            f.push_back(line.substr(s, t - s));
            s = t + 1;
        }
        const std::string& tag = f[0];
        auto wf = [&](size_t i) { return i < f.size() ? Utf8ToWide(f[i].data(), f[i].size()) : std::wstring(); };

        if (tag == "STATE")      m.state = wf(1);
        else if (tag == "HEAD")  m.head = wf(1);
        else if (tag == "TEXT")  { if (!textAcc.empty()) textAcc += L"\r\n"; textAcc += wf(1); }
        else if (tag == "NODE" && f.size() >= 4) {
            int depth = atoi(f[1].c_str());
            if (depth < 0) depth = 0;
            if (depth > 20) depth = 20;
            m.nodes.push_back({ depth, f[2] == "x", wf(3) });
        }
        else if (tag == "JSON")  m.json = wf(1);
        else if (tag == "END")   m.complete = true;
        // V, META and unknown tags are ignored on purpose.
    }
    m.text = textAcc;
}

static void ErrorModel(Model& m, const wchar_t* why)
{
    m.state = L"error";
    m.head = L"Content Credentials couldn't be checked";
    m.text = why;
    m.nodes.clear();
    m.json.clear();
    m.complete = true;
}

// ------------------------------------------------------------------ sandboxed helper launch

// A low-integrity restricted copy of our own token: the helper can read the file and
// the trust lists but cannot write to the user's profile or registry.
static HANDLE MakeLowIntegrityToken()
{
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &hTok))
        return nullptr;
    HANDLE hRestricted = nullptr;
    BOOL ok = CreateRestrictedToken(hTok, DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr, 0, nullptr, &hRestricted);
    CloseHandle(hTok);
    if (!ok) return nullptr;

    PSID sid = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-16-4096", &sid)) { CloseHandle(hRestricted); return nullptr; }   // Low mandatory level
    TOKEN_MANDATORY_LABEL tml = {};
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = sid;
    ok = SetTokenInformation(hRestricted, TokenIntegrityLevel, &tml, sizeof(tml) + GetLengthSid(sid));
    LocalFree(sid);
    if (!ok) { CloseHandle(hRestricted); return nullptr; }
    return hRestricted;
}

// Give the low-integrity helper somewhere it is allowed to write temp files.
static std::wstring EnsureLowTempDir(const std::wstring& base)
{
    std::wstring dir = base + L"\\tmp-low";
    CreateDirectoryW(dir.c_str(), nullptr);
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;OICI;NW;;;LW)", SDDL_REVISION_1, &psd, nullptr)) {
        PACL sacl = nullptr; BOOL present = FALSE, defaulted = FALSE;
        if (GetSecurityDescriptorSacl(psd, &present, &sacl, &defaulted) && present) {
            SetNamedSecurityInfoW(&dir[0], SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, sacl);
        }
        LocalFree(psd);
    }
    return dir;
}

// Copy of our environment with TEMP/TMP redirected (CreateProcess wants a double-NUL block).
static std::vector<wchar_t> BuildEnvBlock(const std::wstring& tempDir)
{
    std::vector<wchar_t> out;
    LPWCH env = GetEnvironmentStringsW();
    if (env) {
        for (LPWCH p = env; *p; ) {
            std::wstring entry(p);
            p += entry.size() + 1;
            if (_wcsnicmp(entry.c_str(), L"TEMP=", 5) == 0 || _wcsnicmp(entry.c_str(), L"TMP=", 4) == 0) continue;
            out.insert(out.end(), entry.begin(), entry.end());
            out.push_back(L'\0');
        }
        FreeEnvironmentStringsW(env);
    }
    for (const wchar_t* k : { L"TEMP=", L"TMP=" }) {
        std::wstring e = std::wstring(k) + tempDir;
        out.insert(out.end(), e.begin(), e.end());
        out.push_back(L'\0');
    }
    out.push_back(L'\0');
    return out;
}

struct Job
{
    std::wstring file;
    HWND hwnd = nullptr;
    std::mutex m;
    HANDLE hProcess = nullptr;
    bool cancelled = false;
    std::string output;
    std::wstring failure;      // non-empty if the helper could not be run at all
    bool timedOut = false;
    bool overflow = false;

    void Terminate(bool timeout)
    {
        std::lock_guard<std::mutex> g(m);
        if (timeout) timedOut = true; else cancelled = true;
        if (hProcess) TerminateProcess(hProcess, 1);
    }
};

static DWORD WINAPI WorkerThread(LPVOID param)
{
    std::shared_ptr<Job>* pp = static_cast<std::shared_ptr<Job>*>(param);
    std::shared_ptr<Job> job = *pp;
    delete pp;

    std::wstring dir = ModuleDir();
    std::wstring exe = dir + L"\\c2paview-helper.exe";
    std::wstring cmd = L"\"" + exe + L"\" --trust-dir \"" + dir + L"\\trust\" -- \"" + LongPathSafe(job->file) + L"\"";
    std::wstring lowTemp = EnsureLowTempDir(dir);
    std::vector<wchar_t> env = BuildEnvBlock(lowTemp);

    if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::lock_guard<std::mutex> g(job->m);
        job->failure = L"The helper program c2paview-helper.exe is missing next to c2paview.dll. Reinstall the C2PA View tab.";
    } else {
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        HANDLE hRead = nullptr, hWrite = nullptr;
        HANDLE hNul = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
        if (hNul == INVALID_HANDLE_VALUE) hNul = nullptr;
        if (CreatePipe(&hRead, &hWrite, &sa, 0)) {
            SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

            STARTUPINFOW si = {};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            si.hStdInput = hNul;
            si.hStdOutput = hWrite;
            si.hStdError = hNul;
            PROCESS_INFORMATION pi = {};
            DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | BELOW_NORMAL_PRIORITY_CLASS;

            HANDLE hTok = MakeLowIntegrityToken();
            BOOL started = FALSE;
            if (hTok) {
                started = CreateProcessAsUserW(hTok, exe.c_str(), &cmd[0], nullptr, nullptr, TRUE, flags, env.data(), dir.c_str(), &si, &pi);
                CloseHandle(hTok);
            }
            if (!started) {
                // Sandbox token unavailable on this system (unusual): still out-of-process, still job-limited.
                started = CreateProcessW(exe.c_str(), &cmd[0], nullptr, nullptr, TRUE, flags, env.data(), dir.c_str(), &si, &pi);
            }
            CloseHandle(hWrite); hWrite = nullptr;

            if (!started) {
                std::lock_guard<std::mutex> g(job->m);
                job->failure = L"The helper program could not be started (error " + std::to_wstring(GetLastError()) + L").";
            } else {
                // Memory / process-count limits, and the helper dies with us.
                HANDLE hJob = CreateJobObjectW(nullptr, nullptr);
                if (hJob) {
                    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = {};
                    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                        JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
                    jeli.BasicLimitInformation.ActiveProcessLimit = 1;
                    jeli.ProcessMemoryLimit = HELPER_MEMORY_LIMIT;
                    SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
                    AssignProcessToJobObject(hJob, pi.hProcess);
                }
                bool go = true;
                {
                    std::lock_guard<std::mutex> g(job->m);
                    if (job->cancelled) go = false; else job->hProcess = pi.hProcess;
                }
                if (go) ResumeThread(pi.hThread); else TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);

                std::string buf;
                char chunk[65536];
                DWORD n = 0;
                while (ReadFile(hRead, chunk, sizeof(chunk), &n, nullptr) && n > 0) {
                    if (buf.size() + n > MAX_OUTPUT_BYTES) {
                        std::lock_guard<std::mutex> g(job->m);
                        job->overflow = true;
                        TerminateProcess(pi.hProcess, 1);
                        break;
                    }
                    buf.append(chunk, n);
                }
                WaitForSingleObject(pi.hProcess, 5000);
                {
                    std::lock_guard<std::mutex> g(job->m);
                    job->hProcess = nullptr;
                    job->output.swap(buf);
                }
                CloseHandle(pi.hProcess);
                if (hJob) CloseHandle(hJob);
            }
            if (hRead) CloseHandle(hRead);
        } else {
            std::lock_guard<std::mutex> g(job->m);
            job->failure = L"Could not create a pipe to the helper program.";
        }
        if (hNul) CloseHandle(hNul);
    }

    {
        std::lock_guard<std::mutex> g(job->m);
        if (!job->cancelled && job->hwnd) PostMessageW(job->hwnd, WM_APP_RESULT, 0, 0);
    }
    job.reset();
    --g_cThreads;
    return 0;
}

// ------------------------------------------------------------------ the page

struct PageState
{
    std::wstring file;
    std::shared_ptr<Job> job;
    HANDLE hThread = nullptr;
    HFONT hHeadFont = nullptr;
    HICON hIcon = nullptr;
    COLORREF headColor = CLR_INVALID;
    Model model;
};

static void SetClipboardText(HWND hwnd, const std::wstring& text)
{
    if (!OpenClipboard(hwnd)) return;
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (h) {
        void* p = GlobalLock(h);
        if (p) { memcpy(p, text.c_str(), bytes); GlobalUnlock(h); SetClipboardData(CF_UNICODETEXT, h); }
        else GlobalFree(h);
    }
    CloseClipboard();
}

static std::wstring DetailsAsText(const PageState& st)
{
    std::wstring t = L"Content Credentials - " + st.file + L"\r\n\r\n" + st.model.head + L"\r\n";
    if (!st.model.text.empty()) t += st.model.text + L"\r\n";
    t += L"\r\n";
    for (const Node& n : st.model.nodes) {
        t.append((size_t)n.depth * 2, L' ');
        t += n.text + L"\r\n";
    }
    return t;
}

static void FillTree(HWND hTree, const Model& m)
{
    TreeView_DeleteAllItems(hTree);
    SendMessageW(hTree, WM_SETREDRAW, FALSE, 0);
    std::vector<HTREEITEM> parents(22, TVI_ROOT);
    std::vector<HTREEITEM> toExpand;
    for (size_t i = 0; i < m.nodes.size(); ++i) {
        const Node& n = m.nodes[i];
        TVINSERTSTRUCTW ins = {};
        ins.hParent = n.depth == 0 ? TVI_ROOT : parents[(size_t)n.depth - 1];
        ins.hInsertAfter = TVI_LAST;
        ins.item.mask = TVIF_TEXT | TVIF_PARAM;
        ins.item.pszText = const_cast<LPWSTR>(n.text.c_str());
        ins.item.lParam = (LPARAM)i;
        HTREEITEM h = TreeView_InsertItem(hTree, &ins);
        if (!h) continue;
        for (size_t d = (size_t)n.depth; d < parents.size(); ++d) parents[d] = h;
        if (n.expanded) toExpand.push_back(h);
    }
    for (HTREEITEM h : toExpand) TreeView_Expand(hTree, h, TVE_EXPAND);
    SendMessageW(hTree, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(hTree, nullptr, TRUE);
}

static void ShowModel(HWND hwnd, PageState& st)
{
    const Model& m = st.model;
    bool present = m.state == L"trusted" || m.state == L"untrusted" || m.state == L"unverified" ||
                   m.state == L"incomplete" || m.state == L"invalid";
    if (m.state == L"invalid" || m.state == L"malformed") st.headColor = RGB(0xB4, 0x23, 0x18);       // alert
    else if (m.state == L"untrusted" || m.state == L"incomplete" || m.state == L"unverified" || m.state == L"remote")
        st.headColor = RGB(0x8A, 0x5A, 0x00);                                                           // warning
    else if (m.state == L"trusted") st.headColor = RGB(0x1B, 0x5E, 0x20);
    else st.headColor = GetSysColor(COLOR_GRAYTEXT);

    ShowWindow(GetDlgItem(hwnd, IDC_ICON), present ? SW_SHOW : SW_HIDE);
    SetDlgItemTextW(hwnd, IDC_HEAD, m.head.c_str());
    SetDlgItemTextW(hwnd, IDC_TEXT, m.text.c_str());
    SetDlgItemTextW(hwnd, IDC_FOOT, L"Checked offline");
    FillTree(GetDlgItem(hwnd, IDC_TREE), m);
    EnableWindow(GetDlgItem(hwnd, IDC_COPY_TEXT), TRUE);
    EnableWindow(GetDlgItem(hwnd, IDC_COPY_JSON), !m.json.empty());
    InvalidateRect(hwnd, nullptr, TRUE);
}

static void StartHelper(HWND hwnd, PageState& st)
{
    auto job = std::make_shared<Job>();
    job->file = st.file;
    job->hwnd = hwnd;
    st.job = job;
    auto* pp = new (std::nothrow) std::shared_ptr<Job>(job);
    if (!pp) { ErrorModel(st.model, L"Out of memory."); ShowModel(hwnd, st); return; }
    ++g_cThreads;
    st.hThread = CreateThread(nullptr, 0, WorkerThread, pp, 0, nullptr);
    if (!st.hThread) {
        --g_cThreads;
        delete pp;
        st.job.reset();
        ErrorModel(st.model, L"Could not start a background thread.");
        ShowModel(hwnd, st);
        return;
    }
    SetTimer(hwnd, IDT_TIMEOUT, HELPER_TIMEOUT_MS, nullptr);
}

static void OnResult(HWND hwnd, PageState& st)
{
    KillTimer(hwnd, IDT_TIMEOUT);
    if (!st.job) return;
    std::string out; std::wstring failure; bool timedOut, overflow;
    {
        std::lock_guard<std::mutex> g(st.job->m);
        out.swap(st.job->output);
        failure = st.job->failure;
        timedOut = st.job->timedOut;
        overflow = st.job->overflow;
    }
    Model m;
    if (!failure.empty()) ErrorModel(m, failure.c_str());
    else {
        ParseOutput(out, m);
        if (timedOut) ErrorModel(m, L"Reading this file took too long and was stopped. Very large files can exceed the time limit.");
        else if (overflow) ErrorModel(m, L"The Content Credentials in this file are too large to display.");
        else if (!m.complete || m.state.empty() || m.head.empty())
            ErrorModel(m, L"The Content Credentials reader stopped unexpectedly while reading this file, so nothing could be verified.");
    }
    st.model = std::move(m);
    ShowModel(hwnd, st);
}

static void OnInitDialog(HWND hwnd, PageState* st)
{
    SetWindowLongPtrW(hwnd, DWLP_USER, (LONG_PTR)st);

    // Bold headline in the dialog's own font.
    HFONT base = (HFONT)SendMessageW(hwnd, WM_GETFONT, 0, 0);
    LOGFONTW lf = {};
    if (base && GetObjectW(base, sizeof(lf), &lf)) {
        lf.lfWeight = FW_SEMIBOLD;
        st->hHeadFont = CreateFontIndirectW(&lf);
        if (st->hHeadFont) SendDlgItemMessageW(hwnd, IDC_HEAD, WM_SETFONT, (WPARAM)st->hHeadFont, TRUE);
    }

    // Icon at the control's real pixel size for the current DPI.
    HWND hIconCtl = GetDlgItem(hwnd, IDC_ICON);
    RECT rc = {};
    GetClientRect(hIconCtl, &rc);
    int cx = rc.right > 0 ? rc.right : 32, cy = rc.bottom > 0 ? rc.bottom : 32;
    int sz = cx < cy ? cx : cy;
    st->hIcon = (HICON)LoadImageW(g_hInst, MAKEINTRESOURCEW(IDI_CR), IMAGE_ICON, sz, sz, LR_DEFAULTCOLOR);
    if (st->hIcon) SendMessageW(hIconCtl, STM_SETICON, (WPARAM)st->hIcon, 0);
    ShowWindow(hIconCtl, SW_HIDE);

    HWND hTree = GetDlgItem(hwnd, IDC_TREE);
    SetWindowTheme(hTree, L"Explorer", nullptr);

    SetDlgItemTextW(hwnd, IDC_HEAD, L"Reading Content Credentials\u2026");
    SetDlgItemTextW(hwnd, IDC_TEXT, L"Checking this file on your PC. Nothing is sent over the network.");
    EnableWindow(GetDlgItem(hwnd, IDC_COPY_TEXT), FALSE);
    EnableWindow(GetDlgItem(hwnd, IDC_COPY_JSON), FALSE);
    st->headColor = GetSysColor(COLOR_WINDOWTEXT);

    StartHelper(hwnd, *st);
}

static void OnDestroy(HWND hwnd, PageState* st)
{
    KillTimer(hwnd, IDT_TIMEOUT);
    if (st->job) {
        st->job->Terminate(false);
        { std::lock_guard<std::mutex> g(st->job->m); st->job->hwnd = nullptr; }
    }
    if (st->hThread) {
        WaitForSingleObject(st->hThread, 5000);   // the terminated helper closes the pipe, so this returns quickly
        CloseHandle(st->hThread);
    }
    if (st->hHeadFont) DeleteObject(st->hHeadFont);
    if (st->hIcon) DestroyIcon(st->hIcon);
    SetWindowLongPtrW(hwnd, DWLP_USER, 0);
    delete st;
}

static INT_PTR CALLBACK PageProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    PageState* st = (PageState*)GetWindowLongPtrW(hwnd, DWLP_USER);
    switch (msg) {
    case WM_INITDIALOG: {
        PROPSHEETPAGEW* psp = (PROPSHEETPAGEW*)lParam;
        PageState* s = (PageState*)psp->lParam;
        psp->lParam = 0;               // the dialog now owns PageState (freed in WM_DESTROY)
        if (s) OnInitDialog(hwnd, s);
        return TRUE;
    }
    case WM_APP_RESULT:
        if (st) OnResult(hwnd, *st);
        return TRUE;
    case WM_TIMER:
        if (wParam == IDT_TIMEOUT && st) {
            KillTimer(hwnd, IDT_TIMEOUT);
            if (st->job) st->job->Terminate(true);   // the worker then posts WM_APP_RESULT
        }
        return TRUE;
    case WM_CTLCOLORSTATIC:
        if (st && (HWND)lParam == GetDlgItem(hwnd, IDC_HEAD)) {
            SetTextColor((HDC)wParam, st->headColor);
            SetBkMode((HDC)wParam, TRANSPARENT);
            return (INT_PTR)GetStockObject(HOLLOW_BRUSH);
        }
        return FALSE;
    case WM_COMMAND:
        if (st && HIWORD(wParam) == BN_CLICKED) {
            if (LOWORD(wParam) == IDC_COPY_TEXT) { SetClipboardText(hwnd, DetailsAsText(*st)); return TRUE; }
            if (LOWORD(wParam) == IDC_COPY_JSON) { SetClipboardText(hwnd, st->model.json); return TRUE; }
        }
        return FALSE;
    case WM_NOTIFY: {
        NMHDR* nm = (NMHDR*)lParam;
        if (st && nm->idFrom == IDC_TREE && nm->code == TVN_GETINFOTIPW) {
            NMTVGETINFOTIPW* tip = (NMTVGETINFOTIPW*)lParam;
            size_t i = (size_t)tip->lParam;
            if (i < st->model.nodes.size() && tip->cchTextMax > 0) {
                wcsncpy_s(tip->pszText, (size_t)tip->cchTextMax, st->model.nodes[i].text.c_str(), _TRUNCATE);
            }
            return TRUE;
        }
        if (nm->code == PSN_APPLY) { SetWindowLongPtrW(hwnd, DWLP_MSGRESULT, PSNRET_NOERROR); return TRUE; }
        return FALSE;
    }
    case WM_DESTROY:
        if (st) OnDestroy(hwnd, st);
        return TRUE;
    }
    return FALSE;
}

// ------------------------------------------------------------------ COM object

class CPropSheetExt : public IShellExtInit, public IShellPropSheetExt
{
    std::atomic<long> m_ref{ 1 };
    std::wstring m_file;
public:
    CPropSheetExt() { ++g_cObj; }
    ~CPropSheetExt() { --g_cObj; }

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IShellExtInit) *ppv = static_cast<IShellExtInit*>(this);
        else if (riid == IID_IShellPropSheetExt) *ppv = static_cast<IShellPropSheetExt*>(this);
        else { *ppv = nullptr; return E_NOINTERFACE; }
        AddRef();
        return S_OK;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return (ULONG)++m_ref; }
    IFACEMETHODIMP_(ULONG) Release() override
    {
        long r = --m_ref;
        if (r == 0) delete this;
        return (ULONG)r;
    }

    // IShellExtInit: only show the tab for exactly one regular file.
    IFACEMETHODIMP Initialize(PCIDLIST_ABSOLUTE, IDataObject* pdtobj, HKEY) override
    {
        if (!pdtobj) return E_INVALIDARG;
        FORMATETC fe = { CF_HDROP, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
        STGMEDIUM stg = {};
        if (FAILED(pdtobj->GetData(&fe, &stg))) return E_FAIL;
        HRESULT hr = E_FAIL;
        HDROP hDrop = (HDROP)GlobalLock(stg.hGlobal);
        if (hDrop) {
            if (DragQueryFileW(hDrop, 0xFFFFFFFF, nullptr, 0) == 1) {
                UINT len = DragQueryFileW(hDrop, 0, nullptr, 0);
                if (len > 0) {
                    std::wstring path(len + 1, L'\0');
                    if (DragQueryFileW(hDrop, 0, &path[0], len + 1) == len) {
                        path.resize(len);
                        DWORD attr = GetFileAttributesW(path.c_str());
                        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                            m_file = path;
                            hr = S_OK;
                        }
                    }
                }
            }
            GlobalUnlock(stg.hGlobal);
        }
        ReleaseStgMedium(&stg);
        return hr;
    }

    // IShellPropSheetExt
    IFACEMETHODIMP AddPages(LPFNSVADDPROPSHEETPAGE pfnAddPage, LPARAM lParam) override
    {
        if (m_file.empty()) return E_FAIL;
        PageState* st = new (std::nothrow) PageState();
        if (!st) return E_OUTOFMEMORY;
        st->file = m_file;

        PROPSHEETPAGEW psp = {};
        psp.dwSize = sizeof(psp);
        psp.dwFlags = PSP_USETITLE | PSP_USECALLBACK;
        psp.hInstance = g_hInst;
        psp.pszTemplate = MAKEINTRESOURCEW(IDD_PAGE);
        psp.pszTitle = L"Content Credentials";
        psp.pfnDlgProc = PageProc;
        psp.pfnCallback = PageCallback;
        psp.lParam = (LPARAM)st;

        HPROPSHEETPAGE hPage = CreatePropertySheetPageW(&psp);
        if (!hPage) { delete st; return E_OUTOFMEMORY; }
        if (!pfnAddPage(hPage, lParam)) { DestroyPropertySheetPage(hPage); return E_FAIL; }   // callback frees st
        return S_OK;
    }
    IFACEMETHODIMP ReplacePage(EXPROPSHEETPAGEID, LPFNSVADDPROPSHEETPAGE, LPARAM) override { return E_NOTIMPL; }

    // The page owns its PageState; it is freed on WM_DESTROY, or here if the page never got created.
    static UINT CALLBACK PageCallback(HWND, UINT uMsg, LPPROPSHEETPAGEW ppsp)
    {
        if (uMsg == PSPCB_CREATE) { ++g_cObj; return 1; }   // keep the DLL loaded while the page lives
        if (uMsg == PSPCB_RELEASE) {
            // Non-null only if the page's dialog was never created (WM_INITDIALOG clears it).
            PageState* st = (PageState*)ppsp->lParam;
            if (st) delete st;
            --g_cObj;
        }
        return 1;
    }
};

class CClassFactory : public IClassFactory
{
    std::atomic<long> m_ref{ 1 };
public:
    CClassFactory() { ++g_cObj; }
    ~CClassFactory() { --g_cObj; }
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) { *ppv = static_cast<IClassFactory*>(this); AddRef(); return S_OK; }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return (ULONG)++m_ref; }
    IFACEMETHODIMP_(ULONG) Release() override
    {
        long r = --m_ref;
        if (r == 0) delete this;
        return (ULONG)r;
    }
    IFACEMETHODIMP CreateInstance(IUnknown* pOuter, REFIID riid, void** ppv) override
    {
        if (!ppv) return E_POINTER;
        *ppv = nullptr;
        if (pOuter) return CLASS_E_NOAGGREGATION;
        CPropSheetExt* p = new (std::nothrow) CPropSheetExt();
        if (!p) return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL fLock) override
    {
        if (fLock) ++g_cLock; else --g_cLock;
        return S_OK;
    }
};

// ------------------------------------------------------------------ exports

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (!ppv) return E_POINTER;
    *ppv = nullptr;
    if (rclsid != CLSID_C2paViewPropSheet) return CLASS_E_CLASSNOTAVAILABLE;
    CClassFactory* f = new (std::nothrow) CClassFactory();
    if (!f) return E_OUTOFMEMORY;
    HRESULT hr = f->QueryInterface(riid, ppv);
    f->Release();
    return hr;
}

STDAPI DllCanUnloadNow()
{
    return (g_cObj == 0 && g_cLock == 0 && g_cThreads == 0) ? S_OK : S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_hInst = hInst;
        DisableThreadLibraryCalls(hInst);
    }
    return TRUE;
}
