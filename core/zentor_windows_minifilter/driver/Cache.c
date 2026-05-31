#include "ZentorAvFilter.h"

/*
 * The first development driver relies on Avorax Guard Service verdict caching.
 * Kernel-mode caching is intentionally left minimal until the communication
 * path is validated under Driver Verifier in a VM.
 */
