#pragma once

#define RST  "\033[0m"

#define _RED  "\033[31m"
#define _GREEN  "\033[32m"
#define _YELLOW  "\033[33m"
#define _BLUE  "\033[34m"
#define _MAGENTA  "\033[35m"
#define _CYAN  "\033[36m"
#define _WHITE  "\033[37m"

#define BOLD(x) "\033[1m" x RST

#define RED(x) _RED x RST
#define GREEN(x) _GREEN x RST
#define YELLOW(x) _YELLOW x RST
#define BLUE(x) _BLUE x RST
#define MAGENTA(x) _MAGENTA x RST
#define CYAN(x) _CYAN x RST
#define WHITE(x) _WHITE x RST
