#ifndef INCLUDED_SURFMODE_HPP
#define INCLUDED_SURFMODE_HPP
#include "ssl/internal.h"  // SurfMode
#include <cstdlib>
#include <iostream>

namespace Surf {
using Mode = SurfMode;

// SURF_TRUE=1 / SURF_ROTATE=1. Both set is an error: each mode preprocesses a
// different circuit set with interactive OT and the two sides must agree.
inline bool mode_from_env(Mode &out) {
  const char *t = ::getenv("SURF_TRUE");
  const char *r = ::getenv("SURF_ROTATE");
  const bool is_true = t && t[0] == '1';
  const bool is_rotate = r && r[0] == '1';
  if (is_true && is_rotate) {
    std::cerr << "SURF_TRUE and SURF_ROTATE are distinct modes; set one\n";
    return false;
  }
  out = is_true ? Mode::True : is_rotate ? Mode::Rotate : Mode::Masked;
  return true;
}

inline const char *mode_name(Mode m) {
  return m == Mode::True ? "TRUE" : m == Mode::Rotate ? "ROTATE" : "MASKED";
}

// Sealed-capture modes share the TRUE record path and circuit set.
inline bool is_capture(Mode m) { return m != Mode::Masked; }
}  // namespace Surf
#endif
