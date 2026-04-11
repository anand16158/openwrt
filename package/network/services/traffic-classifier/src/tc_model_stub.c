#include "tc_model.h"
#include <string.h>

/*
 * Stub implementation when no treelite-compiled model is linked.
 * The classifier falls back to domain-aware heuristics.
 *
 * To replace this stub with a real model:
 *   1. Run training/export_treelite.py to generate C source
 *   2. Replace this file with the generated tc_model_wrapper.c
 *   3. Add the generated tree code files to the Makefile
 */

int tc_model_predict(const float *features, float *output)
{
	(void)features;
	memset(output, 0, sizeof(float) * TC_MODEL_N_CLASSES);
	return 0;
}

int tc_model_available(void)
{
	return 0;
}
