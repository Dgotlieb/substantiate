"""Identifiers that belong to somebody else.

A report naming ``fork()`` or ``find_package()`` is not claiming this repository
declares them, and reporting "no matching declaration" for a C standard library
function or a CMake command is a false finding with a confident tone. These are
resolved as SKIPPED with an explanation instead.

The lists are deliberately conservative: a name here is never checked against
the repository, so a project that genuinely declares its own ``open()`` wrapper
would lose that check. Only add identifiers that are unambiguously external and
that a project would not plausibly define itself.

Contributions welcome -- this is a data file, and extending it needs no
understanding of the rest of the system. Add the identifier to the right set
and a line to the test in tests/test_verify_code.py.
"""

from __future__ import annotations

# C standard library and POSIX. Restricted to names no project would shadow.
LIBC = frozenset(
    {
        "abort", "accept", "access", "alarm", "atexit", "atoi", "atol", "bind",
        "calloc", "chdir", "chmod", "chown", "clearerr", "close", "closedir",
        "connect", "dup", "dup2", "execl", "execve", "exit", "fclose", "fcntl",
        "fdopen", "feof", "ferror", "fflush", "fgets", "fopen", "fork", "fprintf",
        "fputs", "fread", "free", "freeaddrinfo", "fseek", "fstat", "ftell",
        "fwrite", "getaddrinfo", "getcwd", "getenv", "geteuid", "getpid",
        "getsockopt", "gettimeofday", "gmtime", "htonl", "htons", "inet_ntop",
        "inet_pton", "ioctl", "isatty", "kill", "listen", "localtime", "longjmp",
        "lseek", "malloc", "memchr", "memcmp", "memcpy", "memmove", "memset",
        "mkdir", "mmap", "munmap", "ntohl", "ntohs", "open", "opendir", "perror",
        "pipe", "poll", "printf", "putenv", "qsort", "raise", "rand", "read",
        "readdir", "realloc", "recv", "recvfrom", "rename", "rewind", "rmdir",
        "select", "send", "sendto", "setjmp", "setsockopt", "setvbuf", "shutdown",
        "signal", "sigaction", "snprintf", "socket", "socketpair", "sprintf",
        "sscanf", "stat", "strcasecmp", "strcat", "strchr", "strcmp", "strcpy",
        "strdup", "strerror", "strftime", "strlen", "strncmp", "strncpy",
        "strrchr", "strstr", "strtol", "strtoul", "symlink", "sysconf", "time",
        "tolower", "toupper", "umask", "unlink", "usleep", "va_arg", "va_end",
        "va_start", "vfprintf", "vsnprintf", "waitpid", "write",
    }
)

# CMake commands. These appear constantly in build documentation and code fences.
CMAKE = frozenset(
    {
        "add_compile_definitions", "add_compile_options", "add_custom_command",
        "add_custom_target", "add_dependencies", "add_executable", "add_library",
        "add_subdirectory", "add_test", "check_c_source_compiles",
        "check_function_exists", "check_include_file", "check_symbol_exists",
        "check_type_size", "cmake_minimum_required", "cmake_policy", "configure_file",
        "elseif", "endforeach", "endfunction", "endif", "endmacro", "endwhile",
        "execute_process", "file", "find_library", "find_package", "find_path",
        "find_program", "foreach", "get_filename_component", "get_target_property",
        "include_directories", "install", "list", "macro", "mark_as_advanced",
        "message", "option", "pkg_check_modules", "project", "set_property",
        "set_target_properties", "string", "target_compile_definitions",
        "target_compile_options", "target_include_directories",
        "target_link_libraries", "target_sources", "try_compile", "unset",
    }
)

# GNU Autotools / m4 macros.
AUTOTOOLS = frozenset(
    {
        "AC_CHECK_FUNCS", "AC_CHECK_HEADERS", "AC_CHECK_LIB", "AC_CONFIG_FILES",
        "AC_CONFIG_HEADERS", "AC_DEFINE", "AC_INIT", "AC_MSG_ERROR",
        "AC_MSG_RESULT", "AC_MSG_WARNING", "AC_OUTPUT", "AC_PREREQ",
        "AC_SUBST", "AM_CONDITIONAL", "AM_INIT_AUTOMAKE", "AS_IF", "LT_INIT",
    }
)

_SOURCES: tuple[tuple[frozenset[str], str], ...] = (
    (LIBC, "C standard library or POSIX"),
    (CMAKE, "CMake command"),
    (AUTOTOOLS, "Autoconf macro"),
)

# The Python standard library, straight from the interpreter rather than a list
# we would have to maintain. "logging.getLogger" and "urllib.request.getproxies"
# are not claims that this project declares anything.
try:  # pragma: no cover - trivially available on every supported version
    import sys

    PYTHON_STDLIB = frozenset(sys.stdlib_module_names)
except AttributeError:  # pragma: no cover - Python < 3.10
    PYTHON_STDLIB = frozenset()


def origin(name: str) -> str | None:
    """Where ``name`` comes from, or None if it is not a known external."""
    base = name.rsplit("::", 1)[-1].rsplit(".", 1)[-1].rsplit("->", 1)[-1]
    for names, label in _SOURCES:
        if base in names:
            return label
    return None


def dotted_root(name: str) -> str | None:
    """The leading component of a dotted name, or None if it is not dotted."""
    head = name.split("::")[0].split("->")[0]
    return head.split(".")[0] if "." in head else None


def stdlib_origin(name: str) -> str | None:
    """A label when ``name`` is rooted in the Python standard library."""
    root = dotted_root(name)
    return "Python standard library" if root and root in PYTHON_STDLIB else None
