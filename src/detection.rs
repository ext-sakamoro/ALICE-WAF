//! Built-in attack pattern detection: `SQLi` / XSS / cmd injection / path traversal / header injection.

/// SQL injection detection patterns.
const SQLI_PATTERNS: &[&str] = &[
    "' or '1'='1",
    "' or 1=1",
    "'; drop table",
    "'; delete from",
    "'; insert into",
    "'; update ",
    "union select",
    "union all select",
    "select * from",
    "select count(",
    "1=1--",
    "1=1#",
    "' or ''='",
    "' or 'a'='a",
    "') or ('1'='1",
    "admin'--",
    "'; exec ",
    "'; execute ",
    "; drop table",
    "' and 1=1",
    "' and '1'='1",
    "order by 1--",
    "group by 1--",
    "having 1=1",
    "benchmark(",
    "sleep(",
    "waitfor delay",
    "load_file(",
    "into outfile",
    "into dumpfile",
    "information_schema",
    "table_name",
    "column_name",
    "concat(",
    "char(",
    "0x",
];

/// Check if input contains SQL injection patterns.
#[must_use]
pub fn detect_sqli(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();
    SQLI_PATTERNS
        .iter()
        .find(|&&pattern| lower.contains(pattern))
        .copied()
        .map(|v| v as _)
}

/// XSS detection patterns.
const XSS_PATTERNS: &[&str] = &[
    "<script",
    "</script>",
    "javascript:",
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "onfocus=",
    "onblur=",
    "onsubmit=",
    "onchange=",
    "onkeydown=",
    "onkeyup=",
    "onkeypress=",
    "ondblclick=",
    "onmouseout=",
    "onmousedown=",
    "onmouseup=",
    "onmousemove=",
    "onresize=",
    "onscroll=",
    "onunload=",
    "<iframe",
    "<object",
    "<embed",
    "<applet",
    "<form",
    "<img src=",
    "expression(",
    "vbscript:",
    "data:text/html",
    "alert(",
    "confirm(",
    "prompt(",
    "document.cookie",
    "document.write",
    "document.domain",
    "window.location",
    "eval(",
    "settimeout(",
    "setinterval(",
    "innerhtml",
    "outerhtml",
    "textcontent",
    "addeventlistener",
    "fromcharcode",
];

/// Check if input contains XSS patterns.
#[must_use]
pub fn detect_xss(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();
    XSS_PATTERNS
        .iter()
        .find(|&&pattern| lower.contains(pattern))
        .copied()
        .map(|v| v as _)
}

const CMD_INJECTION_PATTERNS: &[&str] = &[
    "; ls",
    "; cat ",
    "; rm ",
    "| ls",
    "| cat ",
    "| rm ",
    "$(",
    "`",
    "; wget ",
    "; curl ",
    "| wget ",
    "| curl ",
    "; chmod ",
    "; chown ",
    "&& ls",
    "&& cat",
    "&& rm",
    "|| ls",
    "|| cat",
    "|| rm",
    "; nc ",
    "; netcat ",
    "; python ",
    "; perl ",
    "; ruby ",
    "; bash ",
    "; sh ",
    "/bin/sh",
    "/bin/bash",
    "cmd.exe",
    "powershell",
];

const PATH_TRAVERSAL_PATTERNS: &[&str] = &[
    "../",
    "..\\",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "%2e%2e%5c",
    "..%5c",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "c:\\windows",
    "c:/windows",
    "/proc/self",
    "/dev/null",
];

const HEADER_INJECTION_PATTERNS: &[&str] = &["\r\n", "%0d%0a", "%0d", "%0a", "\\r\\n"];

/// Check for command injection.
#[must_use]
pub fn detect_command_injection(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();
    CMD_INJECTION_PATTERNS
        .iter()
        .find(|&&pattern| lower.contains(pattern))
        .copied()
        .map(|v| v as _)
}

/// Check for path traversal.
#[must_use]
pub fn detect_path_traversal(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();
    PATH_TRAVERSAL_PATTERNS
        .iter()
        .find(|&&pattern| lower.contains(pattern))
        .copied()
        .map(|v| v as _)
}

/// Check for header injection.
#[must_use]
pub fn detect_header_injection(input: &str) -> Option<&'static str> {
    let lower = input.to_lowercase();
    HEADER_INJECTION_PATTERNS
        .iter()
        .find(|&&pattern| lower.contains(pattern))
        .copied()
        .map(|v| v as _)
}
