#include "smallclue.h"
#include <stdbool.h>
bool pscalRuntimeStderrIsInteractive(void) { return true; }
bool pscalRuntimeStdoutIsInteractive(void) { return true; }
const char *pscal_program_version_string(void) { return "1.0"; }
int smallclueRunEditor(int argc, char **argv) { return 0; }
int smallclueRunMicro(int argc, char **argv) { return 0; }
int smallclueRunSsh(int argc, char **argv) { return 0; }
int smallclueRunScp(int argc, char **argv) { return 0; }
int smallclueRunSftp(int argc, char **argv) { return 0; }
int smallclueRunSshKeygen(int argc, char **argv) { return 0; }
int smallclueRunSshCopyId(int argc, char **argv) { return 0; }
int smallclueRunRsync(int argc, char **argv) { return 0; }
int smallclueGitCommand(int argc, char **argv) { return 0; }
int main(int argc, char **argv) { return smallclueMain(argc, argv); }
