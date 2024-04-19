#pragma once
#include "icvar.h"
extern ICvar* g_pCVar;
struct Color {
public:
	Color(int r_, int g_, int b_) : r(r_), g(g_), b(b_) {};
	int r;
	int g;
	int b;
};