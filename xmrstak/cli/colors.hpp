#pragma once

#if defined(_WIN32) && !defined(VT100)
  // Dumb terminal

  #define BEL ""
  #define ESC ""
  #define RST ""

  #define BOLD(x) x
  #define TITLE(x) x

  #define RED(x) x
  #define GREEN(x) x
  #define YELLOW(x) x
  #define BLUE(x) x
  #define MAGENTA(x) x
  #define CYAN(x) x
  #define WHITE(x) x

#else
  // VT100 compliant terminal

  #define BEL "\007"
  #define ESC "\033"
  #define RST ESC "[0m"

  #define _RED  ESC "[31m"
  #define _GREEN  ESC "[32m"
  #define _YELLOW  ESC "[33m"
  #define _BLUE  ESC "[34m"
  #define _MAGENTA  ESC "[35m"
  #define _CYAN  ESC "[36m"
  #define _WHITE  ESC "[37m"

  #define BOLD(x) ESC "[1m" x RST
  #define TITLE(x) ESC "]0;" x BEL

  #define RED(x) _RED x RST
  #define GREEN(x) _GREEN x RST
  #define YELLOW(x) _YELLOW x RST
  #define BLUE(x) _BLUE x RST
  #define MAGENTA(x) _MAGENTA x RST
  #define CYAN(x) _CYAN x RST
  #define WHITE(x) _WHITE x RST
#endif
